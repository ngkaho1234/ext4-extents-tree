#include "ext4.h"
#include "ext4_bitmap.h"
#include "db.h"

uint64_t size_of_bitmap(ext4_fsblk_t nrblocks)
{
	return (nrblocks >> 3) + ((nrblocks % 8)?1:0);
}

int blocks_of_bitmap(struct super_block *sb, ext4_fsblk_t nrblocks)
{
	uint64_t bitmapsz = size_of_bitmap(nrblocks);
	return (bitmapsz >> sb->s_blocksize_bits)
		+ ((bitmapsz % sb->s_blocksize)?1:0);
}

struct db_bitmap *load_all_bitmap(struct super_block *sb, ext4_fsblk_t nrblocks, ext4_fsblk_t bitmap_block)
{
	int i, err = 0;
	int bitmap_nrblocks = blocks_of_bitmap(sb, nrblocks);
	uint8_t *bitmap = NULL;
	struct db_bitmap_desc *desc = NULL;
	struct db_bitmap *db_bitmap = xzalloc(sizeof(struct db_bitmap));
	if (!db_bitmap)
		return NULL;

	bitmap = xzalloc(bitmap_nrblocks << sb->s_blocksize_bits);
	if (!bitmap) {
		xfree(db_bitmap);
		return NULL;
	}

	desc = xzalloc(sizeof(struct db_bitmap_desc) * bitmap_nrblocks);

	for (i = 0;i < bitmap_nrblocks;i++) {
		struct buffer_head *bh;
		bh = fs_bread(sb, bitmap_block + i, &err);
		if (err)
			goto out;

		memcpy(bitmap + (i << sb->s_blocksize_bits), bh->b_data,
			sb->s_blocksize);
		fs_brelse(bh);
	}
out:
	if (err) {
		if (db_bitmap)
			xfree(db_bitmap);
		if (bitmap)
			xfree(bitmap);
		if (desc)
			xfree(desc);

		db_bitmap = NULL;
	} else {
		db_bitmap->sb = sb;
		db_bitmap->bitmap_count = bitmap_nrblocks;
		db_bitmap->bitmap = bitmap;
		db_bitmap->bitmap_desc = desc;
		db_bitmap->bitmap_block = bitmap_block;
	}
	return db_bitmap;
}

void free_all_bitmap(struct db_bitmap *db_bitmap)
{
	xfree(db_bitmap->bitmap);
	xfree(db_bitmap->bitmap_desc);
	xfree(db_bitmap);
}

void save_all_bitmap(struct super_block *sb, struct db_bitmap *db_bitmap)
{
	int i, err = 0;
	int bitmap_nrblocks = db_bitmap->bitmap_count;
	uint8_t *bitmap = db_bitmap->bitmap;
	ext4_fsblk_t bitmap_block = db_bitmap->bitmap_block;

	for (i = 0;i < bitmap_nrblocks;i++) {
		struct buffer_head *bh;
		if (db_bitmap->bitmap_desc[i].dirty) {
			bh = fs_bwrite(sb, bitmap_block + i, &err);
			if (err)
				goto out;

			memcpy(bh->b_data, bitmap + (i << sb->s_blocksize_bits),
				sb->s_blocksize);
			fs_mark_buffer_dirty(bh);
			fs_brelse(bh);
			db_bitmap->bitmap_desc[i].dirty = 0;
		}
	}
out:
	return;
}

void bitmap_bits_set(struct db_bitmap *db_bitmap, ext4_fsblk_t bit)
{
	uint8_t *bitmap = db_bitmap->bitmap;
	int bitmap_block = bit >> (db_bitmap->sb->s_blocksize_bits << 3);
	*(bitmap + (bit >> 3)) |= (1 << (bit & 7));
	db_bitmap->bitmap_desc[bitmap_block].dirty = 1;
}

static inline void __bitmap_bits_clr(struct db_bitmap *db_bitmap, uint8_t *bitmap, ext4_fsblk_t bit)
{
	int bitmap_block = ((bitmap - db_bitmap->bitmap) >>
		db_bitmap->sb->s_blocksize_bits) +
		(bit >> (db_bitmap->sb->s_blocksize_bits << 3));
	*(bitmap + (bit >> 3)) &= ~(1 << (bit & 7));
	db_bitmap->bitmap_desc[bitmap_block].dirty = 1;
}

void bitmap_bits_clr(struct db_bitmap *db_bitmap, ext4_fsblk_t bit)
{
	uint8_t *bitmap = db_bitmap->bitmap;
	int bitmap_block = bit >> (db_bitmap->sb->s_blocksize_bits << 3);
	*(bitmap + (bit >> 3)) &= ~(1 << (bit & 7));
	db_bitmap->bitmap_desc[bitmap_block].dirty = 1;
}

static inline bool bitmap_is_bit_set(uint8_t *bitmap, ext4_fsblk_t bit)
{
    return (*(bitmap + (bit >> 3)) & (1 << (bit & 7)));
}

static inline bool bitmap_is_bit_clr(uint8_t *bitmap, ext4_fsblk_t bit)
{
    return !bitmap_is_bit_set(bitmap, bit);
}

void bitmap_bits_free(struct db_bitmap *db_bitmap, ext4_fsblk_t bit, uint32_t bcnt)
{
    ext4_fsblk_t i = bit;
    uint8_t *bitmap = db_bitmap->bitmap;

    while(i & 7){

        if(!bcnt)
            return;

        __bitmap_bits_clr(db_bitmap, bitmap, i);

        bcnt--;
        i++;
    }
    bit  = i;
    bitmap += (bit >> 3);

    while(bcnt >= 32){
        *(uint32_t *)bitmap = 0;
        bitmap += 4;
        bcnt -= 32;
        bit += 32;
    }

    while(bcnt >= 16){
        *(uint16_t *)bitmap = 0;
        bitmap += 2;
        bcnt -= 16;
        bit += 16;
    }

    while(bcnt >= 8){
        *bitmap = 0;
        bitmap += 1;
        bcnt -= 8;
        bit += 8;
    }

    for (i = 0; i < bcnt; ++i) {
        __bitmap_bits_clr(db_bitmap, bitmap, i);
    }
}

int bitmap_find_bits_clr(struct db_bitmap *db_bitmap, ext4_fsblk_t bit, ext4_fsblk_t ebit,
    ext4_fsblk_t *bit_id)
{
    ext4_fsblk_t i;
    uint64_t bcnt = ebit - bit + 1;
    uint8_t *bitmap = db_bitmap->bitmap;

    i = bit;

    while(i & 7){

        if(!bcnt)
            return -ENOSPC;

        if(bitmap_is_bit_clr(bitmap, i)){
            *bit_id = bit;
            return 0;
        }

        i++;
        bcnt--;
    }

    bit  = i;
    bitmap += (bit >> 3);


    while(bcnt >= 32){
        if(*(uint32_t *)bitmap != 0xFFFFFFFF)
            goto finish_it;

        bitmap += 4;
        bcnt -= 32;
        bit += 32;
    }

    while(bcnt >= 16){
        if(*(uint16_t *)bitmap != 0xFFFF)
            goto finish_it;

        bitmap += 2;
        bcnt -= 16;
        bit += 16;
    }

    finish_it:
    while(bcnt >= 8){
        if(*bitmap != 0xFF){
            for (i = 0; i < 8; ++i) {
                if(bitmap_is_bit_clr(bitmap, i)){
                    *bit_id = bit + i;
                    return 0;
                }
            }
        }

        bitmap += 1;
        bcnt -= 8;
        bit += 8;
    }

    for (i = 0; i < bcnt; ++i) {
        if(bitmap_is_bit_clr(bitmap, i)){
            *bit_id = bit + i;
            return 0;
        }
    }

    return -ENOSPC;
}
