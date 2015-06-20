#ifndef _EXT4_JBD2_H
#define _EXT4_JBD2_H


typedef int handle_t;

/*
 * Wrapper functions with which ext4 calls into JBD.
 */
int __ext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh);

int __ext4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, ext4_fsblk_t blocknr);

int __ext4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh);

int __ext4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh);

#define ext4_journal_get_write_access(handle, bh) \
	__ext4_journal_get_write_access(__func__, __LINE__, (handle), (bh))
#define ext4_forget(handle, is_metadata, inode, bh, block_nr) \
	__ext4_forget(__func__, __LINE__, (handle), (is_metadata), (inode), \
		      (bh), (block_nr))
#define ext4_journal_get_create_access(handle, bh) \
	__ext4_journal_get_create_access(__func__, __LINE__, (handle), (bh))
#define ext4_handle_dirty_metadata(handle, inode, bh) \
	__ext4_handle_dirty_metadata(__func__, __LINE__, (handle), (inode), \
				     (bh))

handle_t *__ext4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks);
int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle);

#define ext4_journal_start_sb(sb, type, nblocks)			\
	__ext4_journal_start_sb((sb), __LINE__, (type), (nblocks), 0)

#define ext4_journal_start(inode, type, nblocks)			\
	__ext4_journal_start((inode), __LINE__, (type), (nblocks), 0)

static inline handle_t *__ext4_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks)
{
	return __ext4_journal_start_sb(inode->i_sb, line, type, blocks,
				       rsv_blocks);
}

#define ext4_journal_stop(handle) \
	__ext4_journal_stop(__func__, __LINE__, (handle))

static inline int ext4_journal_extend(handle_t *handle, int nblocks)
{
	return 0;
}

#endif
