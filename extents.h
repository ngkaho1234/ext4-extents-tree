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

#define CONFIG_EXT4_EXT_TYPES
#ifdef CONFIG_EXT4_EXT_TYPES

typedef u8 __ext4_u8;
typedef u16 __ext4_u16;
typedef u32 __ext4_u32;
typedef u64 __ext4_u64;

typedef s8 __ext4_s8;
typedef s16 __ext4_s16;
typedef s32 __ext4_s32;
typedef s64 __ext4_s64;

typedef __le16	__ext4_le16;
typedef __le32	__ext4_le32;
typedef __le64	__ext4_le64;

typedef __be16	__ext4_be16;
typedef __be32	__ext4_be32;
typedef __be64	__ext4_be64;

#define ext4_cpu_to_be64(_n) cpu_to_be64(_n)
#define ext4_cpu_to_be32(_n) cpu_to_be32(_n)
#define ext4_cpu_to_be16(_n) cpu_to_be16(_n)

#define ext4_cpu_to_le64(_n) cpu_to_le64(_n)
#define ext4_cpu_to_le32(_n) cpu_to_le32(_n)
#define ext4_cpu_to_le16(_n) cpu_to_le16(_n)

#define ext4_be64_to_cpu(_n) be64_to_cpu(_n)
#define ext4_be32_to_cpu(_n) be32_to_cpu(_n)
#define ext4_be16_to_cpu(_n) be16_to_cpu(_n)

#define ext4_le64_to_cpu(_n) le64_to_cpu(_n)
#define ext4_le32_to_cpu(_n) le32_to_cpu(_n)
#define ext4_le16_to_cpu(_n) le16_to_cpu(_n)

static inline void ext4_le16_add_cpu(__ext4_le16 *var, __ext4_u16 val)
{
	*var = ext4_cpu_to_le16(ext4_le16_to_cpu(*var) + val);
}

static inline void ext4_le32_add_cpu(__ext4_le32 *var, __ext4_u32 val)
{
	*var = ext4_cpu_to_le32(ext4_le32_to_cpu(*var) + val);
}

static inline void ext4_le64_add_cpu(__ext4_le64 *var, __ext4_u64 val)
{
	*var = ext4_cpu_to_le64(ext4_le64_to_cpu(*var) + val);
}

static inline void ext4_be16_add_cpu(__ext4_be16 *var, __ext4_u16 val)
{
	*var = ext4_cpu_to_be16(ext4_be16_to_cpu(*var) + val);
}

static inline void ext4_be32_add_cpu(__ext4_be32 *var, __ext4_u32 val)
{
	*var = ext4_cpu_to_be32(ext4_be32_to_cpu(*var) + val);
}

static inline void ext4_be64_add_cpu(__ext4_be64 *var, __ext4_u64 val)
{
	*var = ext4_cpu_to_be64(ext4_be64_to_cpu(*var) + val);
}

#endif /* CONFIG_EXT4_EXT_TYPES */

#pragma pack(push, 1)

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
struct ext4_extent {
	__ext4_le32	ee_block;		/* first logical block extent covers */
	__ext4_le16	ee_len;			/* number of blocks covered by extent */
	__ext4_le16	ee_start_hi;	/* high 16 bits of physical block */
	__ext4_le32	ee_start_lo;	/* low 32 bits of physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct ext4_extent_idx {
	__ext4_le32	ei_block; /* Index covers logical blocks from 'block' */

	/**
	 * Pointer to the physical block of the next
	 * level. leaf or next index could be there
	 * high 16 bits of physical block
	 */
	__ext4_le32	ei_leaf_lo;	/* pointer to the physical block of the next level */
	__ext4_le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__ext4_u16	ei_unused;
};

union ext4_extent_item {
	struct ext4_extent e;
	struct ext4_extent_idx i;
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct ext4_extent_header {
	__ext4_le16	eh_magic;		/* probably will support different formats */
	__ext4_le16	eh_entries;		/* number of valid entries */
	__ext4_le16	eh_max;			/* capacity of store in entries */
	__ext4_le16	eh_depth;		/* has tree real underlying blocks? */
	__ext4_le32	eh_generation;	/* generation of the tree */
};

#pragma pack(pop)


#define EXT4_EXT_MAGIC 0xF30A

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^15 and not (2^16 - 1), since we use the
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
#define EXT_INIT_MAX_LEN (1L << 15)
#define EXT_UNWRITTEN_MAX_LEN (EXT_INIT_MAX_LEN - 1)

#define EXT_EXTENT_SIZE sizeof(struct ext4_extent)
#define EXT_INDEX_SIZE sizeof(struct ext4_extent_idx)

#define EXT_FIRST_EXTENT(__hdr__) \
	((struct ext4_extent *) (((char *) (__hdr__)) +		\
				 sizeof(struct ext4_extent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct ext4_extent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct ext4_extent_header)))
#define EXT_FIRST_ITEM(__hdr__) \
	((union ext4_extent_item *) (((char *) (__hdr__)) +	\
				     sizeof(struct ext4_extent_header)))
#define EXT_HAS_FREE_INDEX(__hdr__) \
	(ext4_le16_to_cpu((__hdr__)->eh_entries) \
				     < ext4_le16_to_cpu((__hdr__)->eh_max))
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_ITEM(__hdr__) \
	(EXT_FIRST_ITEM((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_MAX_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_max) - 1)
#define EXT_MAX_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_max) - 1)
#define EXT_MAX_ITEM(__hdr__) \
	(EXT_FIRST_ITEM((__hdr__)) + ext4_le16_to_cpu((__hdr__)->eh_max) - 1)

#define EXT4_EXT_TAIL_OFFSET(hdr)                                           \
	(sizeof(struct ext4_extent_header) +                                   \
	 (sizeof(struct ext4_extent) * (hdr)->eh_max))

#define EXT4_EXT_ITEM_SIZE sizeof(union ext4_extent_item)

/*
 * ext4_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
#define EXT4_EXT_MAX_LBLK (ext4_lblk_t)-1

#define EXT4_EXT_ROOT_SIZE (EXT4_INODE_BLOCKS * sizeof(uint32_t))

static inline struct ext4_extent_header *ext4_ext_inode_hdr(struct inode *inode)
{
	return (struct ext4_extent_header *) inode->i_data;
}

static inline struct ext4_extent_header *ext4_ext_block_hdr(void *data)
{
	return (struct ext4_extent_header *)data;
}

struct ext4_ext_cursor *
ext4_ext_cursor_alloc(
		struct super_block *sb,
		void *root,
		void *fsinfo,
		size_t blocksz);

int
ext4_ext_lookup_extent(
		struct ext4_ext_cursor *cur,
		ext4_lblk_t lblock,
		bool *notfound);

void
ext4_ext_cursor_free(struct ext4_ext_cursor *cur);

int
ext4_ext_insert(struct ext4_ext_cursor *cur, struct ext4_extent *newext);

int
ext4_ext_delete(struct ext4_ext_cursor *cur);

int
ext4_ext_decrement(struct ext4_ext_cursor *cur, bool *noprevp);

int
ext4_ext_increment(struct ext4_ext_cursor *cur, bool *nonextp);

struct ext4_extent *
ext4_ext_cursor_ext(struct ext4_ext_cursor *cur);

void
ext4_ext_init_i_blocks(struct ext4_extent_header *hdr);

#endif /* _NEW_BTREE_H */
