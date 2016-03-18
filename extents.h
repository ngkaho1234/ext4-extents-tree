#ifndef _NEW_BTREE_H
#define _NEW_BTREE_H

/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */


/*
 * With AGGRESSIVE_TEST defined, the capacity of index/leaf blocks
 * becomes very small, so index split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and extents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_

/*
 * ext4_inode has i_data array (60 bytes total).
 * The first 12 bytes store ext4_extent_header;
 * the remainder stores an array of ext4_extent.
 * For non-inode extent blocks, ext4_extent_tail
 * follows the array.
 */

/*
 * This is the extent tail on-disk structure.
 * All other extent structures are 12 bytes long.  It turns out that
 * block_size % 12 >= 4 for at least all powers of 2 greater than 512, which
 * covers all valid ext4 block sizes.  Therefore, this tail structure can be
 * crammed into the end of the block without having to rebalance the tree.
 */
struct ext4_extent_tail
{
	uint32_t et_checksum; /* crc32c(uuid+inum+extent_block) */
};

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
struct ext4_extent
{
	uint64_t ee_block;    /* first logical block extent covers */
	uint32_t ee_len;      /* number of blocks covered by extent */
	uint64_t ee_start; /* physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct ext4_extent_idx
{
	uint64_t ei_block;   /* index covers logical blocks from 'block' */
	uint64_t ei_leaf; /* pointer to the physical block of the next *
					       * level. leaf or next index could
			      * be there */
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct ext4_extent_header
{
	uint16_t eh_magic;      /* probably will support different formats */
	uint16_t eh_entries;    /* number of valid entries */
	uint16_t eh_max;	/* capacity of store in entries */
	uint16_t eh_depth;      /* has tree real underlying blocks? */
	uint32_t eh_generation; /* generation of the tree */
};

#define EXT4_EXT_MAGIC (0xf30a)

#define EXT4_EXTENT_TAIL_OFFSET(hdr)                                           \
	(sizeof(struct ext4_extent_header) +                                   \
	 (sizeof(struct ext4_extent) * (hdr)->eh_max))

static inline struct ext4_extent_tail *
find_ext4_extent_tail(struct ext4_extent_header *eh)
{
	return (struct ext4_extent_tail *)(((void *)eh) +
					   EXT4_EXTENT_TAIL_OFFSET(eh));
}

/*
 * Array of ext4_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct ext4_ext_path
{
	ext4_fsblk_t p_block;
	int p_depth;
	int p_maxdepth;
	struct ext4_extent *p_ext;
	struct ext4_extent_idx *p_idx;
	struct ext4_extent_header *p_hdr;
	struct buffer_head *p_bh;
};

/*
 * structure for external API
 */

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^31 and not (2^32 - 1), since we use the
 * MSB of ee_len field in the extent datastructure to signify if this
 * particular extent is an initialized extent or an uninitialized (i.e.
 * preallocated).
 * EXT_UNINIT_MAX_LEN is the maximum number of blocks we can have in an
 * uninitialized extent.
 * If ee_len is <= 0x8000, it is an initialized extent. Otherwise, it is an
 * uninitialized one. In other words, if MSB of ee_len is set, it is an
 * uninitialized extent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an uninitialized extent of zero length and
 * thus we make it as a special case of initialized extent with 0x8000 length.
 * This way we get better extent-to-group alignment for initialized extents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * extent is 2^15 (32768) and in an *uninitialized* extent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN (1 << 31)
#define EXT_UNWRITTEN_MAX_LEN	(EXT_INIT_MAX_LEN - 1)

#define EXT_EXTENT_SIZE sizeof(struct ext4_extent)
#define EXT_INDEX_SIZE sizeof(struct ext4_extent_idx)

#define EXT_FIRST_EXTENT(__hdr__)                                              \
	((struct ext4_extent *)(((char *)(__hdr__)) +                          \
				sizeof(struct ext4_extent_header)))
#define EXT_FIRST_INDEX(__hdr__)                                               \
	((struct ext4_extent_idx *)(((char *)(__hdr__)) +                      \
				    sizeof(struct ext4_extent_header)))
#define EXT_HAS_FREE_INDEX(__path__)                                           \
	((__path__)->p_hdr->eh_entries < (__path__)->p_hdr->eh_max)
#define EXT_LAST_EXTENT(__hdr__)                                               \
	(EXT_FIRST_EXTENT((__hdr__)) + (__hdr__)->eh_entries - 1)
#define EXT_LAST_INDEX(__hdr__)                                                \
	(EXT_FIRST_INDEX((__hdr__)) + (__hdr__)->eh_entries - 1)
#define EXT_MAX_EXTENT(__hdr__)                                                \
	(EXT_FIRST_EXTENT((__hdr__)) + (__hdr__)->eh_max - 1)
#define EXT_MAX_INDEX(__hdr__)                                                 \
	(EXT_FIRST_INDEX((__hdr__)) + (__hdr__)->eh_max - 1)

static inline struct ext4_extent_header *ext_inode_hdr(struct inode *inode)
{
	return (struct ext4_extent_header *) inode->i_data;
}

static inline struct ext4_extent_header *ext_block_hdr(struct buffer_head *bh)
{
	return (struct ext4_extent_header *)bh->b_data;
}

static inline uint16_t ext_depth(struct inode *inode)
{
	return le16_to_cpu(ext_inode_hdr(inode)->eh_depth);
}

static inline uint16_t ext4_ext_get_actual_len(struct ext4_extent *ext)
{
	return (le32_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		le32_to_cpu(ext->ee_len) :
		(le32_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void ext4_ext_mark_initialized(struct ext4_extent *ext)
{
	ext->ee_len = cpu_to_le32(ext4_ext_get_actual_len(ext));
}

static inline void ext4_ext_mark_unwritten(struct ext4_extent *ext)
{
	ext->ee_len |= cpu_to_le32(EXT_INIT_MAX_LEN);
}

static inline int ext4_ext_is_unwritten(struct ext4_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (le32_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

static inline ext4_lblk_t ext4_ext_lblock(struct ext4_extent *ex)
{
	return le64_to_cpu(ex->ee_block);
}

static inline ext4_lblk_t ext4_idx_lblock(struct ext4_extent_idx *ix)
{
	return le64_to_cpu(ix->ei_block);
}

/*
 * ext4_ext_pblock:
 * combine low and high parts of physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_ext_pblock(struct ext4_extent *ex)
{
	return le64_to_cpu(ex->ee_start);
}

/*
 * ext4_idx_pblock:
 * combine low and high parts of a leaf physical block number into ext4_fsblk_t
 */
static inline ext4_fsblk_t ext4_idx_pblock(struct ext4_extent_idx *ix)
{
	return le64_to_cpu(ix->ei_leaf);
}

static inline void ext4_ext_store_lblock(struct ext4_extent *ex,
				       ext4_lblk_t lblk)
{
	ex->ee_block = cpu_to_le64(lblk);
}

static inline void ext4_idx_store_lblock(struct ext4_extent_idx *ix,
				       ext4_lblk_t lblk)
{
	ix->ei_block = cpu_to_le64(lblk);
}

/*
 * ext4_ext_store_pblock:
 * stores a large physical block number into an extent struct,
 * breaking it into parts
 */
static inline void ext4_ext_store_pblock(struct ext4_extent *ex,
					 ext4_fsblk_t pb)
{
	ex->ee_start = cpu_to_le64(pb);
}

/*
 * ext4_idx_store_pblock:
 * stores a large physical block number into an index struct,
 * breaking it into parts
 */
static inline void ext4_idx_store_pblock(struct ext4_extent_idx *ix,
					 ext4_fsblk_t pb)
{
	ix->ei_leaf = cpu_to_le64(pb);
}

#define ext4_ext_dirty(handle, inode, path)                                           \
	__ext4_ext_dirty(__func__, __LINE__, (handle), (inode), (path))


int ext4_ext_get_blocks(void *handle, struct inode *inode, ext4_lblk_t iblock,
			unsigned long max_blocks, struct buffer_head *bh_result,
			int create);

void ext4_ext_init(struct super_block *sb);

int ext4_ext_tree_init(void *handle, struct inode *inode);

int ext4_ext_truncate(struct inode *inode, ext4_lblk_t from,
			  ext4_lblk_t to);

#endif /* _NEW_BTREE_H */
