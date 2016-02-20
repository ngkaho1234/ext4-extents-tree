#include "ext4.h"
#include <sys/mman.h>

static int fs_bh_alloc = 0;
static int fs_bh_freed = 0;

void fs_start_trans(struct super_block *sb)
{
	__sync_fetch_and_add((int *)&sb->s_fs_info, 1);
}

void fs_stop_trans(struct super_block *sb)
{
	UNUSED(sb);
}

struct buffer_head *fs_bread(struct super_block *sb, ext4_fsblk_t block, int *ret)
{
	int err = 0;
	struct buffer_head *bh;
	bh = sb_getblk(sb, block);
	if (!bh)
		return NULL;

	if (bh->b_private != sb->s_fs_info &&
	    buffer_dirty(bh) &&
	    buffer_uptodate(bh)) {
		write_dirty_buffer(bh);
	}

	err = bh_submit_read(bh);
	wait_on_buffer(bh);
	if (ret)
		*ret = err;

	bh->b_private = sb->s_fs_info;
	fs_bh_alloc++;

	return bh;
}

struct buffer_head *fs_bwrite(struct super_block *sb, ext4_fsblk_t block, int *ret)
{
	int err = 0;
	struct buffer_head *bh;
	bh = sb_getblk(sb, block);
	if (ret)
		*ret = err;

	if (bh &&
	    bh->b_private != sb->s_fs_info &&
	    buffer_dirty(bh) &&
	    buffer_uptodate(bh)) {
		write_dirty_buffer(bh);
	}

	if (bh) {
		bh->b_private = sb->s_fs_info;
		fs_bh_alloc++;
	}

	return bh;
}

void fs_brelse(struct buffer_head *bh)
{
	fs_bh_freed++;
	brelse(bh);
}

void fs_mark_buffer_dirty(struct buffer_head *bh)
{
	set_buffer_uptodate(bh);
	set_buffer_dirty(bh);
}

void fs_bforget(struct buffer_head *bh)
{
	clear_buffer_uptodate(bh);
	clear_buffer_dirty(bh);
	fs_brelse(bh);
}

void fs_bh_showstat(void)
{
	printf("fs_bh_alloc: %d, fs_bh_freed: %d\n", fs_bh_alloc,
		fs_bh_freed);
}
