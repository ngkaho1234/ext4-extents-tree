#ifndef _EXT4_H
#define _EXT4_H

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <malloc.h>
#include "kerncompat.h"
#include "buffer.h"

/*
 * Memory management
 */
#define ext4_malloc(sz) malloc(sz)
#define ext4_zalloc(sz) calloc(1, sz)
#define ext4_free(addr) free(addr)

/*
 * Types of integer.
 */
typedef uint16_t ext4_extlen_t;
typedef uint32_t ext4_lblk_t;
typedef uint64_t ext4_fsblk_t;


#define EXT4_INODE_BLOCKS 15

/*
 * Soon we will change this with a real inode structure.
 */
struct inode {
	struct super_block *i_sb;
	uint8_t i_uuid[16]; /* For compability only. */
	struct db_handle *i_db; /* For testing purpose. */
	uint32_t i_inum;
	uint32_t i_generation;
	uint32_t i_csum;
	int	 i_ino;
	uint64_t i_size;
	union {
		uint32_t i_data[EXT4_INODE_BLOCKS];
		uint32_t i_block[EXT4_INODE_BLOCKS];
	};
	int	 i_data_dirty:1;
	int (*i_writeback)(struct inode *inode);
};

#include "extents.h"
#include "extents_bh.h"
#include "db.h"

uint32_t ext4_crc32c(uint32_t crc, const void *buf, size_t size);

#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

#endif	/* _EXT4_H */
