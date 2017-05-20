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
	ihdr = ext4_ext_inode_hdr(inode);
	memcpy(ihdr, db->db_header->db_tree_base, sizeof(inode->i_data));

	if (ihdr->eh_magic != EXT4_EXT_MAGIC) {
		ext4_ext_init_i_blocks(ihdr);
		inode->i_data_dirty = 1;
	}

	inode->i_db = db;

	return inode;
}

/*
 * ext4_ext_lblk - combine low and high parts of physical block number into ext4_fsblk_t
 */
static inline ext4_lblk_t ext4_ext_lblk(struct ext4_extent *ex)
{
	return ext4_le32_to_cpu(ex->ee_block);
}

/*
 * ext4_idx_lblk - combine low and high parts of a leaf physical block number into ext4_fsblk_t
 */
static inline ext4_lblk_t ext4_idx_lblk(struct ext4_extent_idx *ix)
{
	return ext4_le32_to_cpu(ix->ei_block);
}

static inline ext4_extlen_t ext4_ext_len(struct ext4_extent *ext)
{
	return (ext4_le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		ext4_le16_to_cpu(ext->ee_len) :
		(ext4_le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

int main(int argc, char **argv)
{
	int dir;
	int err = 0;
	struct inode *inode;
	time_t a, b;
	ext4_lblk_t from;
	bool notfound;
	struct ext4_ext_cursor *cur;

	if (argc < 4)
		return EXIT_FAILURE;

	from = strtoul(argv[2], NULL, 0);
	dir = atoi(argv[3]);
	if (dir != 1 && dir != -1)
		return EXIT_FAILURE;

	a = clock();
	inode = open_ext4_db(argv[1]);

	cur = ext4_ext_cursor_alloc(
			inode->i_sb,
			inode->i_data,
			inode,
			inode->i_sb->s_blocksize);
	err = ext4_ext_lookup_extent(cur, from, &notfound);
	if (err) {
		fprintf(stderr, "err: %s, block: %" PRIu32 "\n",
				strerror(err), from);
		ext4_ext_cursor_free(cur);
		return EXIT_FAILURE;
	}
	if (notfound) {
		fprintf(stderr, "Block: %" PRIu32 " not found\n", from);
		return EXIT_FAILURE;
	}

	while (1) {
		struct ext4_extent *ext;
		if (dir == -1) {
			bool noprev;
			err = ext4_ext_decrement(cur, &noprev);
			if (err || noprev)
				break;
		} else {
			bool nonext;
			err = ext4_ext_increment(cur, &nonext);
			if (err || nonext)
				break;
		}
		ext = ext4_ext_cursor_ext(cur);
		printf("Extents start: %" PRIu32 " len: %" PRIu16 "\n",
				ext4_ext_lblk(ext), ext4_ext_len(ext));
	}
	ext4_ext_cursor_free(cur);

	b = clock();
	fprintf(stderr, "err: %s, clock: %ld\n", strerror(-err), (b - a)/CLOCKS_PER_SEC);
	free_ext4_db(inode);

	return 0;
}
