#ifndef _SIMPLE_DB_H
#define _SIMPLE_DB_H

#include "ext4.h"
#include <stdint.h>

#define DB_MAGIC 0xeeeeeeee
#define DB_BLOCKSIZE_BITS 12

struct db_header {
	uint32_t db_magic;
	uint64_t db_nrblocks;
	uint64_t db_bitmap_block;
	uint32_t db_tree_base[15];
	uint8_t db_name[255];
} __attribute__((__packed__));

struct db_info {
	uint8_t db_name[255];
	uint64_t db_nrblocks;
	uint32_t db_tree_base[15];
} __attribute__((__packed__));

struct db_bitmap_desc {
	int dirty:1;
};

struct db_bitmap {
	struct super_block *sb;
	uint8_t *bitmap;
	struct db_bitmap_desc *bitmap_desc;
	int bitmap_count;
	ext4_fsblk_t bitmap_block;
};

struct db_handle {
	struct super_block *sb;
	struct inode *sb_inode;
	struct db_header *db_header;
	struct db_bitmap *db_bitmap;
	struct buffer_head *sb_bh;
};

struct db_bitmap *load_all_bitmap(struct super_block *sb, ext4_fsblk_t nrblocks, ext4_fsblk_t bitmap_block);

void free_all_bitmap(struct db_bitmap *db_bitmap);

void save_all_bitmap(struct super_block *sb, struct db_bitmap *db_bitmap);

uint64_t size_of_bitmap(ext4_fsblk_t nrblocks);

int blocks_of_bitmap(struct super_block *sb, ext4_fsblk_t nrblocks);

void bitmap_bits_set(struct db_bitmap *db_bitmap, ext4_fsblk_t bit);

void bitmap_bits_clr(struct db_bitmap *db_bitmap, ext4_fsblk_t bit);

void bitmap_bits_free(struct db_bitmap *db_bitmap, ext4_fsblk_t bit, uint32_t bcnt);

int bitmap_find_bits_clr(struct db_bitmap *db_bitmap, ext4_fsblk_t bit, ext4_fsblk_t ebit,
    ext4_fsblk_t *bit_id);

struct db_handle *db_open(struct super_block *sb);

void db_close(struct db_handle *db_handle);

#endif
