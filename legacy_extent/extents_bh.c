#include "ext4.h"

static int fs_bh_alloc = 0;
static int fs_bh_freed = 0;

struct buffer_head *fs_bread(struct super_block *sb, ext4_fsblk_t block, int *ret)
{
	int err = 0;
	struct buffer_head *bh = sb_getblk(sb, block);
	if (!bh) {
		err = -ENOMEM;
		goto out;
	}

	err = bh_submit_read(bh);
	if (err) {
		brelse(bh);
		bh = NULL;
		goto out;
	}
	lock_buffer(bh);
out:
	if (ret)
		*ret = err;
	if (bh)
		fs_bh_alloc++;

	return bh;
}

struct buffer_head *fs_bwrite(struct super_block *sb, ext4_fsblk_t block, int *ret)
{
	int err = 0;
	struct buffer_head *bh = sb_getblk(sb, block);
	if (!bh) {
		err = -ENOMEM;
		goto out;
	}

	lock_buffer(bh);
out:
	if (ret)
		*ret = err;
	if (bh)
		fs_bh_alloc++;

	return bh;
}

void fs_brelse(struct buffer_head *bh)
{
	unlock_buffer(bh);

	fs_bh_freed++;
	brelse(bh);
}

void fs_mark_buffer_dirty(struct buffer_head *bh)
{
	unlock_buffer(bh);
	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);
	lock_buffer(bh);
}

void fs_bforget(struct buffer_head *bh)
{
	clear_buffer_uptodate(bh);
	unlock_buffer(bh);

	fs_bh_freed++;
	bforget(bh);
}

void fs_bh_showstat(void)
{
	printf("fs_bh_alloc: %d, fs_bh_freed: %d\n", fs_bh_alloc,
		fs_bh_freed);
}
