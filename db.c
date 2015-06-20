#include "db.h"

struct db_handle *db_open(struct super_block *sb)
{
	struct buffer_head *bh;
	struct db_header *bhdr;
	struct db_handle *db_handle;
	struct db_bitmap *db_bitmap;
	int err = 0;
	db_handle = kzalloc(sizeof(struct db_handle), GFP_NOFS);
	if (!db_handle)
		return NULL;

	bh = fs_bread(sb, 0, &err);
	if (!bh) {
		err = -ENOMEM;
		goto out;
	}
	bhdr = (struct db_header *)bh->b_data;
	db_handle->sb = sb;
	db_handle->db_header = (struct db_header *)bhdr;
	db_bitmap = load_all_bitmap(sb, bhdr->db_nrblocks, bhdr->db_bitmap_block);
	if (!db_handle) {
		err = -ENOMEM;
		goto out;
	}
	db_handle->db_bitmap = db_bitmap;
	db_handle->sb_bh = bh;
out:
	if (err) {
		if (db_bitmap)
			free_all_bitmap(db_bitmap);
		if (db_handle)
			kfree(db_handle);

		db_handle = NULL;
	}
	return db_handle;
}

void db_close(struct db_handle *db_handle)
{
	save_all_bitmap(db_handle->sb, db_handle->db_bitmap);
	free_all_bitmap(db_handle->db_bitmap);
	fs_brelse(db_handle->sb_bh);
	kfree(db_handle);
}
