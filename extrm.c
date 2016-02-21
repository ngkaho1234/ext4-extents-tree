#include "ext4.h"
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int inode_writeback(struct inode *inode)
{
	int ret = 0;
	if (inode->i_data_dirty) {
		if (inode->i_writeback)
			ret = inode->i_writeback(inode);
		if (!ret)
			inode->i_data_dirty = 0;

	}
	return ret;
}

static void inode_free(struct inode *inode)
{
	inode_writeback(inode);
	xfree(inode);
}

static struct inode *inode_alloc(struct super_block *sb)
{
	struct inode *inode;
	inode = xzalloc(sizeof(struct inode));
	inode->i_sb = sb;
	inode->i_generation = 0;
	inode->i_data_dirty = 0;
	return inode;
}

static int inode_sb_writeback(struct inode *inode)
{
	memcpy(inode->i_db->db_header->db_tree_base, inode->i_data,
			sizeof(inode->i_data));
	fs_mark_buffer_dirty(inode->i_db->sb_bh);
	return 0;
}

static void free_ext4_db(struct inode *inode)
{
	struct db_handle *db_handle = inode->i_db;
	struct block_device *bdev = inode->i_sb->s_bdev;

	inode_free(inode);
	db_close(db_handle);
	bdev_free(bdev);
	fs_bh_showstat();
}

static struct inode *open_ext4_db(char *file)
{
	int fd;
	struct ext4_extent_header *ihdr;
	struct inode *inode;
	struct db_handle *db;
	struct block_device *bdev;

	fd = device_open(file);

	bdev = bdev_alloc(fd, 12);
	inode = inode_alloc(bdev->bd_super);

	/* For testing purpose, those data is hard-coded. */
	inode->i_writeback = inode_sb_writeback;
	memset(inode->i_uuid, 0xCC, sizeof(inode->i_uuid));
	inode->i_inum = 45;
	inode->i_csum = ext4_crc32c(~0, inode->i_uuid, sizeof(inode->i_uuid));
	inode->i_csum =
	    ext4_crc32c(inode->i_csum, &inode->i_inum, sizeof(inode->i_inum));
	inode->i_csum = ext4_crc32c(inode->i_csum, &inode->i_generation,
				    sizeof(inode->i_generation));

	if (!device_size(bdev))
		exit(EXIT_FAILURE);

	db = db_open(inode->i_sb);
	ihdr = ext_inode_hdr(inode);
	memcpy(ihdr, db->db_header->db_tree_base, sizeof(inode->i_data));

	if (ihdr->eh_magic != EXT4_EXT_MAGIC) {
		ext4_ext_tree_init(NULL, inode);
		inode->i_data_dirty = 1;
	}

	inode->i_db = db;

	return inode;
}

int ext4_find_extent(struct inode *inode, ext4_lblk_t block,
		 struct ext4_ext_path **orig_path, int flags);
int ext4_ext_remove_extent(struct inode *inode, struct ext4_ext_path *path);
void ext4_ext_drop_refs(struct ext4_ext_path *path, int keep_other);

int main(int argc, char **argv)
{
	int err = 0;
	struct inode *inode;
	time_t a, b;
	ext4_lblk_t from;
	struct ext4_ext_path *path = NULL;

	if (argc < 3)
		return -1;

	from = strtol(argv[2], NULL, 0);

	inode = open_ext4_db(argv[1]);
	a = clock();
	do {
		struct ext4_extent *ex;
		err = ext4_find_extent(inode, from, &path, 0);
		if (err)
			break;

		ex = path[ext_depth(inode)].p_ext;
		if (!ex) {
			err = -ENOENT;
			break;
		}
	        if (in_range(from, le32_to_cpu(ex->ee_block),
			     le16_to_cpu(ex->ee_len)))
			err = ext4_ext_remove_extent(inode, path);
		else
			err = -ENOENT;

	} while(0);

	if (path) {
		ext4_ext_drop_refs(path, false);
		xfree(path);
	}

	b = clock();
	fprintf(stderr, "err: %s, clock: %ld\n", strerror(-err), (b - a)/CLOCKS_PER_SEC);
	free_ext4_db(inode);

	return 0;
}
