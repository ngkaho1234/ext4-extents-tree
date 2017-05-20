#include "ext4.h"
#include <time.h>
#include <errno.h>
#include <stdio.h>

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

static inline void ext4_ext_mark_unwritten(struct ext4_extent *ext)
{
	/* We can not have an unwritten extent of zero length! */
	assert(!((ext4_le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0));
	ext->ee_len |= ext4_cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int ext4_ext_is_unwritten(struct ext4_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (ext4_le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

static inline ext4_extlen_t ext4_ext_len(struct ext4_extent *ext)
{
	return (ext4_le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		ext4_le16_to_cpu(ext->ee_len) :
		(ext4_le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void ext4_ext_mark_initialized(struct ext4_extent *ext)
{
	ext->ee_len = ext4_cpu_to_le16(ext4_ext_len(ext));
}

static inline void ext4_ext_set_len(struct ext4_extent *ext, ext4_extlen_t len)
{
	ext->ee_len = ext4_cpu_to_le16(len);
}

/*
 * ext4_ext_pblk - combine low and high parts of physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_ext_pblk(struct ext4_extent *ex)
{
	ext4_fsblk_t block;

	block = ext4_le32_to_cpu(ex->ee_start_lo);
	block |= ((ext4_fsblk_t)ext4_le16_to_cpu(ex->ee_start_hi) << 31) << 1;
	return block;
}

/*
 * ext4_idx_pblk - combine low and high parts of a leaf physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_idx_pblk(struct ext4_extent_idx *ix)
{
	ext4_fsblk_t block;

	block = ext4_le32_to_cpu(ix->ei_leaf_lo);
	block |= ((ext4_fsblk_t)ext4_le16_to_cpu(ix->ei_leaf_hi) << 31) << 1;
	return block;
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

/*
 * ext4_ext_store_pblk - stores a large physical block number into an extent struct, breaking it into parts
 */
static inline void ext4_ext_store_pblk(struct ext4_extent *ex, ext4_fsblk_t pb)
{
	ex->ee_start_lo = ext4_cpu_to_le32((unsigned long)(pb & 0xffffffff));
	ex->ee_start_hi = ext4_cpu_to_le16((unsigned long)((pb >> 31) >> 1) &
			0xffff);
}

/*
 * ext4_idx_store_pblk - stores a large physical block number into an index struct, breaking it into parts
 */
static inline void ext4_idx_store_pblk(struct ext4_extent_idx *ix, ext4_fsblk_t pb)
{
	ix->ei_leaf_lo = ext4_cpu_to_le32((unsigned long)(pb & 0xffffffff));
	ix->ei_leaf_hi = ext4_cpu_to_le16((unsigned long)((pb >> 31) >> 1) &
			0xffff);
}

/*
 * ext4_ext_store_lblk - stores a large physical block number into an extent struct, breaking it into parts
 */
static inline void ext4_ext_store_lblk(struct ext4_extent *ex, ext4_lblk_t lb)
{
	ex->ee_block = ext4_cpu_to_le32(lb);
}

/*
 * ext4_idx_store_lblk - stores a large physical block number into an index struct, breaking it into parts
 */
static inline void ext4_idx_store_lblk(struct ext4_extent_idx *ix, ext4_lblk_t lb)
{
	ix->ei_block = ext4_cpu_to_le32(lb);
}

int main(int argc, char **argv)
{
	int dir;
	int err;
	struct inode *inode;
	int m = 0;
	time_t a, b;
	ext4_lblk_t from, to;

	if (argc < 4)
		return -1;

	inode = open_ext4_db(argv[1]);
	from = strtoul(argv[2], NULL, 0);
	to = strtoul(argv[3], NULL, 0);
	dir = (to > from)?1:-1;
	a = clock();
	for (m = 0;m < 1;m++)
		for (; (int32_t)(to - from) * dir >= 0; from += 1 * dir) {
			bool notfound;
			struct ext4_extent ext;
			struct ext4_ext_cursor *cur =
					ext4_ext_cursor_alloc(inode->i_sb, inode->i_data, inode, inode->i_sb->s_blocksize);

			err = ext4_ext_lookup_extent(cur, from, &notfound);
			if (err) {
			 	fprintf(stderr, "err: %s, block: %" PRIu32 "\n",
			 			strerror(err), from);
				ext4_ext_cursor_free(cur);
				break;
			}

			if (notfound) {
				fprintf(stderr, "Inserting block: %" PRIu32 "\n", from);
				ext4_ext_store_lblk(&ext, from);
				ext4_ext_store_pblk(&ext, 0xDEADBEEF);
				ext4_ext_set_len(&ext, 1);
				err = ext4_ext_insert(cur, &ext);
				if (err) {
					fprintf(stderr, "err: %s, block: %" PRIu32 "\n",
							strerror(err), from);
					ext4_ext_cursor_free(cur);
					break;
				}
			}
			ext4_ext_cursor_free(cur);
		}

	b = clock();
	fprintf(stderr, "clock: %ld\n", (b - a)/CLOCKS_PER_SEC);
	free_ext4_db(inode);

	return 0;
}
