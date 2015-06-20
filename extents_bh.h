#ifndef _EXTENTS_BH_H
#define _EXTENTS_BH_H

struct buffer_head *fs_bread(struct super_block *sb, ext4_fsblk_t block, int *ret);

void fs_brelse(struct buffer_head *bh);

struct buffer_head *fs_bwrite(struct super_block *sb, ext4_fsblk_t block, int *ret);

void fs_mark_buffer_dirty(struct buffer_head *bh);

void fs_bforget(struct buffer_head *bh);

void fs_bh_showstat(void);

#endif
