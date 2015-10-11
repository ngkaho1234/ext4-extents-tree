#include "ext4.h"
#include <memory.h>
#include <string.h>
#include <malloc.h>

/*
 * used by extent splitting.
 */
#define EXT4_EXT_MAY_ZEROOUT	0x1  /* safe to zeroout if split fails \
					due to ENOSPC */
#define EXT4_EXT_MARK_UNWRIT1	0x2  /* mark first half unwritten */
#define EXT4_EXT_MARK_UNWRIT2	0x4  /* mark second half unwritten */

#define EXT4_EXT_DATA_VALID1	0x8  /* first half contains valid data */
#define EXT4_EXT_DATA_VALID2	0x10 /* second half contains valid data */

/*#ifdef _EXTENTS_TEST*/
#if 1
static inline int ext4_mark_inode_dirty(struct inode *inode)
{
	inode->i_data_dirty = 1;
	return 0;
}

#define ext4_inode_to_goal_block(inode) (0)

static inline int ext4_allocate_single_block(struct inode *inode,
					     ext4_fsblk_t fake,
					     ext4_fsblk_t *blockp,
					     unsigned long count)
{
	int err;
	err = bitmap_find_bits_clr(inode->i_db->db_bitmap, 0,
			inode->i_db->db_header->db_nrblocks - 1,
			blockp);
	if (!err)
		bitmap_bits_set(inode->i_db->db_bitmap, *blockp);

	return err;
}

static ext4_fsblk_t ext4_new_meta_blocks(struct inode *inode,
			ext4_fsblk_t goal,
			unsigned int flags,
			unsigned long *count, int *errp)
{
	ext4_fsblk_t block = 0;
	unsigned long nrblocks = (count)?(*count):1;

	*errp = ext4_allocate_single_block(inode, goal, &block, nrblocks);
	if (count)
		*count = 1;
	return block;
}

static void ext4_ext_free_blocks(struct inode *inode,
				 ext4_fsblk_t block, int count, int flags)
{
	bitmap_bits_free(inode->i_db->db_bitmap, block, count);
}

#define ext_debug printf
#endif

static inline int ext4_ext_space_block(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 6)
		size = 6;
#endif
	return size;
}

static inline int ext4_ext_space_block_idx(struct inode *inode, int check)
{
	int size;

	size = (inode->i_sb->s_blocksize - sizeof(struct ext4_extent_header))
			/ sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 5)
		size = 5;
#endif
	return size;
}

static inline int ext4_ext_space_root(struct inode *inode, int check)
{
	int size;

	size = sizeof(inode->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 3)
		size = 3;
#endif
	return size;
}

static inline int ext4_ext_space_root_idx(struct inode *inode, int check)
{
	int size;

	size = sizeof(inode->i_data);
	size -= sizeof(struct ext4_extent_header);
	size /= sizeof(struct ext4_extent_idx);
#ifdef AGGRESSIVE_TEST
	if (!check && size > 4)
		size = 4;
#endif
	return size;
}

static int ext4_ext_max_entries(struct inode *inode, int depth, int check)
{
	int max;

	if (depth == ext_depth(inode)) {
		if (depth == 0)
			max = ext4_ext_space_root(inode, check);
		else
			max = ext4_ext_space_root_idx(inode, check);
	} else {
		if (depth == 0)
			max = ext4_ext_space_block(inode, check);
		else
			max = ext4_ext_space_block_idx(inode, check);
	}

	return max;
}

static ext4_fsblk_t ext4_ext_find_goal(struct inode *inode,
			      struct ext4_ext_path *path,
			      ext4_lblk_t block)
{
	if (path) {
		int depth = path->p_depth;
		struct ext4_extent *ex;

		/*
		 * Try to predict block placement assuming that we are
		 * filling in a file which will eventually be
		 * non-sparse --- i.e., in the case of libbfd writing
		 * an ELF object sections out-of-order but in a way
		 * the eventually results in a contiguous object or
		 * executable file, or some database extending a table
		 * space file.  However, this is actually somewhat
		 * non-ideal if we are writing a sparse file such as
		 * qemu or KVM writing a raw image file that is going
		 * to stay fairly sparse, since it will end up
		 * fragmenting the file system's free space.  Maybe we
		 * should have some hueristics or some way to allow
		 * userspace to pass a hint to file system,
		 * especially if the latter case turns out to be
		 * common.
		 */
		ex = path[depth].p_ext;
		if (ex) {
			ext4_fsblk_t ext_pblk = ext4_ext_pblock(ex);
			ext4_lblk_t ext_block = le32_to_cpu(ex->ee_block);

			if (block > ext_block)
				return ext_pblk + (block - ext_block);
			else
				return ext_pblk - (ext_block - block);
		}

		/* it looks like index is empty;
		 * try to find starting block from index itself */
		if (path[depth].p_bh)
			return path[depth].p_bh->b_blocknr;
	}

	/* OK. use inode's group */
	return ext4_inode_to_goal_block(inode);
}

/*
 * Allocation for a meta data block
 */
static ext4_fsblk_t
ext4_ext_new_meta_block(struct inode *inode,
			struct ext4_ext_path *path,
			struct ext4_extent *ex, int *err, unsigned int flags)
{
	ext4_fsblk_t goal, newblock;

	goal = ext4_ext_find_goal(inode, path, le32_to_cpu(ex->ee_block));
	newblock = ext4_new_meta_blocks(inode, goal, flags,
					NULL, err);
	return newblock;
}

static int __ext4_ext_dirty(struct inode *inode,
		      struct ext4_ext_path *path)
{
	int err;

	if (path->p_bh) {
		/*ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));*/
		/* path points to block */
		err = 0;
		fs_mark_buffer_dirty(path->p_bh);
	} else {
		/* path points to leaf/index in inode body */
		err = ext4_mark_inode_dirty(inode);
	}
	return err;
}

void ext4_ext_drop_refs(struct ext4_ext_path *path, int keep_other)
{
	int depth, i;

	if (!path)
		return;
	if (keep_other)
		depth = 0;
	else
		depth = path->p_depth;

	for (i = 0; i <= depth; i++, path++)
		if (path->p_bh) {
			fs_brelse(path->p_bh);
			path->p_bh = NULL;
		}
}

static uint32_t ext4_ext_block_csum(struct inode *inode,
				    struct ext4_extent_header *eh)
{
	return ext4_crc32c(inode->i_csum, eh, EXT4_EXTENT_TAIL_OFFSET(eh));
}

static void ext4_extent_block_csum_set(struct inode *inode,
				    struct ext4_extent_header *eh)
{
	struct ext4_extent_tail *tail;

	tail = find_ext4_extent_tail(eh);
	tail->et_checksum = ext4_ext_block_csum(
			inode, eh);
}

/*
 * Check that whether the basic information inside the extent header
 * is correct or not.
 */
static int ext4_ext_check(struct inode *inode,
			    struct ext4_extent_header *eh, int depth,
			    ext4_fsblk_t pblk)
{
	struct ext4_extent_tail *tail;
	const char *error_msg;
	int max = 0;

	if (eh->eh_magic != EXT4_EXT_MAGIC) {
		error_msg = "invalid magic";
		goto corrupted;
	}
	if (le16_to_cpu(eh->eh_depth) != depth) {
		error_msg = "unexpected eh_depth";
		goto corrupted;
	}
	if (eh->eh_max == 0) {
		error_msg = "invalid eh_max";
		goto corrupted;
	}
	if (le16_to_cpu(eh->eh_entries) > le16_to_cpu(eh->eh_max)) {
		error_msg = "invalid eh_entries";
		goto corrupted;
	}

	tail = find_ext4_extent_tail(eh);
	if (tail->et_checksum != ext4_ext_block_csum(inode, eh)) {
		/* FIXME: Warning: extent checksum damaged? */
	}

	return 0;

corrupted:
	return -EIO;
}

static struct buffer_head *
read_extent_tree_block(struct inode *inode, ext4_fsblk_t pblk, int depth,
			 int *perr, int flags)
{
	struct buffer_head		*bh;
	int				err;

	if (perr)
		*perr = 0;

	bh = fs_bread(inode->i_sb, pblk, &err);
	if (!bh) {
		err = -ENOMEM;
		goto errout;
	}

	if (buffer_verified(bh))
		goto out;
	err = ext4_ext_check(inode,
			       ext_block_hdr(bh), depth, pblk);
	if (err)
		goto errout;
	set_buffer_verified(bh);
out:
	return bh;
errout:
	if (bh)
		fs_brelse(bh);
	if (perr)
		*perr = err;
	return NULL;
}

/*
 * ext4_ext_binsearch_idx:
 * binary search for the closest index of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch_idx(struct inode *inode,
			struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ei_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_idx = l - 1;

}

/*
 * ext4_ext_binsearch:
 * binary search for closest extent of the given block
 * the header must be checked before calling this
 */
static void
ext4_ext_binsearch(struct inode *inode,
		struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent *r, *l, *m;

	if (eh->eh_entries == 0) {
		/*
		 * this leaf is empty:
		 * we get such a leaf in split/add case
		 */
		return;
	}

	l = EXT_FIRST_EXTENT(eh) + 1;
	r = EXT_LAST_EXTENT(eh);

	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < le32_to_cpu(m->ee_block))
			r = m - 1;
		else
			l = m + 1;
	}

	path->p_ext = l - 1;

}

static ext4_fsblk_t ext4_bh_block(struct buffer_head *bh)
{
	return bh->b_blocknr;
}

#define EXT4_EXT_PATH_INC_DEPTH 1

int ext4_find_extent(struct inode *inode, ext4_lblk_t block,
		 struct ext4_ext_path **orig_path, int flags)
{
	struct ext4_extent_header *eh;
	struct buffer_head *bh;
	ext4_fsblk_t buf_block = 0;
	struct ext4_ext_path *path = *orig_path;
	int depth, i, ppos = 0;
	int ret;

	eh = ext_inode_hdr(inode);
	depth = ext_depth(inode);

	if (path) {
		ext4_ext_drop_refs(path, 0);
		if (depth > path[0].p_maxdepth) {
			kfree(path);
			*orig_path = path = NULL;
		}
	}
	if (!path) {
		int path_depth = depth + EXT4_EXT_PATH_INC_DEPTH;
		/* account possible depth increase */
		path = kzalloc(sizeof(struct ext4_ext_path) *
					(path_depth + 1),
				GFP_NOFS);
		if (!path)
			return -ENOMEM;
		path[0].p_maxdepth = path_depth;
	}
	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	/* walk through the tree */
	while (i) {
		ext4_ext_binsearch_idx(inode, path + ppos, block);
		path[ppos].p_block = ext4_idx_pblock(path[ppos].p_idx);
		path[ppos].p_depth = i;
		path[ppos].p_ext = NULL;
		buf_block = path[ppos].p_block;

		i--;
		ppos++;
		if (!path[ppos].p_bh ||
		    ext4_bh_block(path[ppos].p_bh) != buf_block) {
			bh = read_extent_tree_block(inode, buf_block, i,
						    &ret, flags);
			if (ret) {
				goto err;
			}
			if (ppos > depth) {
				fs_brelse(bh);
				ret = -EIO;
				goto err;
			}

			eh = ext_block_hdr(bh);
			path[ppos].p_bh = bh;
			path[ppos].p_hdr = eh;
		}
	}

	path[ppos].p_depth = i;
	path[ppos].p_ext = NULL;
	path[ppos].p_idx = NULL;

	/* find extent */
	ext4_ext_binsearch(inode, path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	*orig_path = path;

	ret = 0;
	return ret;

err:
	ext4_ext_drop_refs(path, 0);
	kfree(path);
	if (orig_path)
		*orig_path = NULL;
	return ret;
}

static int ext4_ext_init_header(struct inode *inode, struct ext4_extent_header *eh, int depth)
{
	eh->eh_entries = 0;
	eh->eh_max = cpu_to_le16(ext4_ext_max_entries(inode, depth, 0));
	eh->eh_magic = cpu_to_le16(EXT4_EXT_MAGIC);
	eh->eh_depth = depth;
}

/*
 * Be cautious, the buffer_head returned is not yet mark dirtied. */
static int ext4_ext_split_node(struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_fsblk_t *sibling,
			       struct buffer_head **new_bh)
{
	int ret;
	ext4_fsblk_t newblock;
	struct buffer_head *bh = NULL;
	int depth = ext_depth(inode);

	assert(sibling);
	assert(new_bh);
	/* FIXME: currently we split at the point after the current extent. */
	newblock = ext4_ext_new_meta_block(inode, path,
					   newext, &ret, 0);
	if (ret)
		goto cleanup;

	/*  For write access.*/
	bh = fs_bwrite(inode->i_sb, newblock, &ret);
	if (!bh)
		goto cleanup;

	if (at == depth) {
		/* start copy from next extent */
		int m = EXT_MAX_EXTENT(path[at].p_hdr) - path[at].p_ext;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(bh);
		ext4_ext_init_header(inode, neh, 0);
		if (m) {
			struct ext4_extent *ex;
			ex = EXT_FIRST_EXTENT(neh);
			memmove(ex, path[at].p_ext + 1, sizeof(struct ext4_extent) * m);
			le16_add_cpu(&neh->eh_entries, m);
			le16_add_cpu(&path[at].p_hdr->eh_entries, -m);
			ret = __ext4_ext_dirty(inode, path + at);
			if (ret)
				goto cleanup;

		}
	} else {
		int m = EXT_MAX_INDEX(path[at].p_hdr) - path[at].p_idx;
		struct ext4_extent_header *neh;
		neh = ext_block_hdr(bh);
		ext4_ext_init_header(inode, neh, depth - at);
		if (m) {
			struct ext4_extent_idx *ix;
			ix = EXT_FIRST_INDEX(neh);
			memmove(ix, path[at].p_idx + 1, sizeof(struct ext4_extent) * m);
			le16_add_cpu(&neh->eh_entries, m);
			le16_add_cpu(&path[at].p_hdr->eh_entries, -m);
			ret = __ext4_ext_dirty(inode, path + at);
			if (ret)
				goto cleanup;

		}
	}
cleanup:
	if (ret) {
		if (bh) {
			fs_brelse(bh);
			bh = NULL;
		}
		if (newblock)
			ext4_ext_free_blocks(inode, newblock, 1, 0);

		newblock = 0;
	}
	*sibling = newblock;
	*new_bh = bh;
	return ret;
}

static ext4_lblk_t ext4_ext_block_index(struct ext4_extent_header *eh)
{
	if (eh->eh_depth)
		return le32_to_cpu(EXT_FIRST_INDEX(eh)->ei_block);
	return le32_to_cpu(EXT_FIRST_EXTENT(eh)->ee_block);
}

#define EXT_INODE_HDR_NEED_GROW 0x1

struct ext_split_trans {
	ext4_fsblk_t	     ptr;
	struct ext4_ext_path path;
	int		     switch_to;
};

static int ext4_ext_insert_index(struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       ext4_lblk_t insert_index,
			       ext4_fsblk_t insert_block,
			       struct ext_split_trans *spt)
{
	int switch_to = 0;
	struct ext4_extent_idx *ix;
	struct ext4_ext_path *curp = path + at;
	struct buffer_head *bh = NULL;
	int len, err;
	struct ext4_extent_header *eh;

	if (curp->p_idx && insert_index == le32_to_cpu(curp->p_idx->ei_block))
		return -EIO;

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(inode, path, at,
						  newext, &spt->ptr, &bh);
			if (err)
				goto out;

			neh = ext_block_hdr(bh);
			if (insert_index >
				le32_to_cpu(curp->p_idx->ei_block)) {
				/* Make decision which node should be used to insert the index.*/
				if (le16_to_cpu(neh->eh_entries) > le16_to_cpu(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ix = EXT_LAST_INDEX(eh) + 1;
				} else {
					eh = neh;
					ix = EXT_FIRST_INDEX(eh);
					switch_to = 1;
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ix = EXT_LAST_INDEX(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_idx == NULL) {
			ix = EXT_FIRST_INDEX(eh);
			curp->p_idx = ix;
		} else if (insert_index > le32_to_cpu(curp->p_idx->ei_block)) {
			/* insert after */
			ix = curp->p_idx + 1;
		} else {
			/* insert before */
			ix = curp->p_idx;
		}
	}

	len = EXT_LAST_INDEX(eh) - ix + 1;
	assert(len >= 0);
	if (len > 0)
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));

	if (ix > EXT_MAX_INDEX(eh)) {
		err = -EIO;
		goto out;
	}

	ix->ei_block = cpu_to_le32(insert_index);
	ext4_idx_store_pblock(ix, insert_block);
	le16_add_cpu(&eh->eh_entries, 1);

	if (ix > EXT_LAST_INDEX(eh)) {
		err = -EIO;
		goto out;
	}

	if (eh == curp->p_hdr)
		err = __ext4_ext_dirty(inode, curp);
	else
		err = 0;

out:
	if (err) {
		if (bh)
			fs_brelse(bh);

		spt->ptr = 0;
	} else if (bh) {
		/* If we got a sibling leaf. */
		fs_mark_buffer_dirty(bh);

		spt->path.p_block = ext4_idx_pblock(ix);
		spt->path.p_depth = cpu_to_le16(eh->eh_depth);
		spt->path.p_maxdepth = 0;
		spt->path.p_ext = NULL;
		spt->path.p_idx = ix;
		spt->path.p_hdr = eh;
		spt->path.p_bh = bh;

		if (switch_to)
			spt->switch_to = 1;
		else {
			curp->p_idx = ix;
			curp->p_block = ext4_idx_pblock(ix);
		}
	
	} else {
		spt->ptr = 0;
		curp->p_idx = ix;
		curp->p_block = ext4_idx_pblock(ix);
	}
	return err;

}

/*
 * ext4_ext_correct_indexes:
 * if leaf gets modified and modified extent is first in the leaf,
 * then we have to correct all indexes above.
 * TODO: do we need to correct tree in all cases?
 */
static int ext4_ext_correct_indexes(struct inode *inode,
				    struct ext4_ext_path *path)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	eh = path[depth].p_hdr;
	ex = path[depth].p_ext;

	if (ex == NULL || eh == NULL) {
		return -EIO;
	}

	if (depth == 0) {
		/* there is no tree at all */
		return 0;
	}

	if (ex != EXT_FIRST_EXTENT(eh)) {
		/* we correct tree if first leaf got modified only */
		return 0;
	}

	/*
	 * TODO: we need correction if border is smaller than current one
	 */
	k = depth - 1;
	border = path[depth].p_ext->ee_block;
	path[k].p_idx->ei_block = border;
	err = __ext4_ext_dirty(inode, path + k);
	if (err)
		return err;

	while (k--) {
		/* change all left-side indexes */
		if (path[k+1].p_idx != EXT_FIRST_INDEX(path[k+1].p_hdr))
			break;
		path[k].p_idx->ei_block = border;
		err = __ext4_ext_dirty(inode, path + k);
		if (err)
			break;
	}

	return err;
}

static inline int ext4_ext_can_prepend(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex2) + ext4_ext_get_actual_len(ex2)
		!= ext4_ext_pblock(ex1))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_is_unwritten(ex1)) {
		if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_UNWRITTEN_MAX_LEN)
			return 0;
	} else if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (le32_to_cpu(ex2->ee_block) + ext4_ext_get_actual_len(ex2) !=
			le32_to_cpu(ex1->ee_block))
		return 0;

	return 1;
}

static inline int ext4_ext_can_append(struct ext4_extent *ex1, struct ext4_extent *ex2)
{
	if (ext4_ext_pblock(ex1) + ext4_ext_get_actual_len(ex1)
		!= ext4_ext_pblock(ex2))
		return 0;

#ifdef AGGRESSIVE_TEST
	if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2) > 4)
		return 0;
#else
	if (ext4_ext_is_unwritten(ex1)) {
		if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_UNWRITTEN_MAX_LEN)
			return 0;
	} else if (ext4_ext_get_actual_len(ex1) + ext4_ext_get_actual_len(ex2)
				> EXT_INIT_MAX_LEN)
		return 0;
#endif

	if (le32_to_cpu(ex1->ee_block) + ext4_ext_get_actual_len(ex1) !=
			le32_to_cpu(ex2->ee_block))
		return 0;

	return 1;
}

static int ext4_ext_insert_leaf(struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext,
			       struct ext_split_trans *spt)
{
	int switch_to = 0;
	struct ext4_ext_path *curp = path + at;
	struct ext4_extent *ex = curp->p_ext;
	struct buffer_head *bh = NULL;
	int len, err, unwritten;
	struct ext4_extent_header *eh;

	if (curp->p_ext && le32_to_cpu(newext->ee_block) == le32_to_cpu(curp->p_ext->ee_block))
		return -EIO;

	if (curp->p_ext && ext4_ext_can_append(curp->p_ext, newext)) {
		unwritten = ext4_ext_is_unwritten(curp->p_ext);
		curp->p_ext->ee_len = cpu_to_le16(ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext));
		if (unwritten)
			ext4_ext_mark_unwritten(curp->p_ext);
		err = __ext4_ext_dirty(inode, curp);
		goto out;

	}

	if (curp->p_ext && ext4_ext_can_prepend(curp->p_ext, newext)) {
		unwritten = ext4_ext_is_unwritten(curp->p_ext);
		curp->p_ext->ee_block = newext->ee_block;
		curp->p_ext->ee_len = cpu_to_le16(ext4_ext_get_actual_len(curp->p_ext)
			+ ext4_ext_get_actual_len(newext));
		if (unwritten)
			ext4_ext_mark_unwritten(curp->p_ext);
		err = __ext4_ext_dirty(inode, curp);
		goto out;

	}

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max)) {
		if (at) {
			struct ext4_extent_header *neh;
			err = ext4_ext_split_node(inode, path, at,
						  newext, &spt->ptr, &bh);
			if (err)
				goto out;

			neh = ext_block_hdr(bh);
			if (le32_to_cpu(newext->ee_block) >
				le32_to_cpu(curp->p_ext->ee_block)) {
				if (le16_to_cpu(neh->eh_entries) > le16_to_cpu(curp->p_hdr->eh_entries)) {
					eh = curp->p_hdr;
					/* insert after */
					ex = EXT_LAST_EXTENT(eh) + 1;
				} else {
					eh = neh;
					ex = EXT_FIRST_EXTENT(eh);
					switch_to = 1;
				}
			} else {
				eh = curp->p_hdr;
				/* insert before */
				ex = EXT_LAST_EXTENT(eh);
			}
		} else {
			err = EXT_INODE_HDR_NEED_GROW;
			goto out;
		}
	} else {
		eh = curp->p_hdr;
		if (curp->p_ext == NULL) {
			ex = EXT_FIRST_EXTENT(eh);
			curp->p_ext = ex;
		} else if (le32_to_cpu(newext->ee_block) > le32_to_cpu(curp->p_ext->ee_block)) {
			/* insert after */
			ex = curp->p_ext + 1;
		} else {
			/* insert before */
			ex = curp->p_ext;
		}
	}

	len = EXT_LAST_EXTENT(eh) - ex + 1;
	assert(len >= 0);
	if (len > 0)
		memmove(ex + 1, ex, len * sizeof(struct ext4_extent));

	if (ex > EXT_MAX_EXTENT(eh)) {
		err = -EIO;
		goto out;
	}

	ex->ee_block = newext->ee_block;
	ex->ee_len = newext->ee_len;
	ext4_ext_store_pblock(ex, ext4_ext_pblock(newext));
	le16_add_cpu(&eh->eh_entries, 1);

	if (ex > EXT_LAST_EXTENT(eh)) {
		err = -EIO;
		goto out;
	}

	if (eh == curp->p_hdr) {
		err = ext4_ext_correct_indexes(inode, path);
		if (err)
			goto out;
		err = __ext4_ext_dirty(inode, curp);
	} else
		err = 0;

out:
	if (err) {
		if (bh)
			fs_brelse(bh);

		spt->ptr = 0;
	} else if (bh) {
		/* If we got a sibling leaf. */
		fs_mark_buffer_dirty(bh);

		spt->path.p_block = ext4_ext_pblock(ex);
		spt->path.p_depth = cpu_to_le16(eh->eh_depth);
		spt->path.p_maxdepth = 0;
		spt->path.p_ext = ex;
		spt->path.p_idx = NULL;
		spt->path.p_hdr = eh;
		spt->path.p_bh = bh;

		if (switch_to)
			spt->switch_to = 1;
		else {
			curp->p_ext = ex;
			curp->p_block = ext4_ext_pblock(ex);
		}

	} else {
		spt->ptr = 0;
		curp->p_ext = ex;
		curp->p_block = ext4_ext_pblock(ex);
	}

	return err;

}

/*
 * ext4_ext_grow_indepth:
 * implements tree growing procedure:
 * - allocates new block
 * - moves top-level data (index block or leaf) into the new block
 * - initializes new top-level, creating index that points to the
 *   just created block
 */
static int ext4_ext_grow_indepth(struct inode *inode,
				 unsigned int flags)
{
	struct ext4_extent_header *neh;
	struct buffer_head *bh;
	ext4_fsblk_t newblock, goal = 0;
	int err = 0;

	/* Try to prepend new index to old one */
	if (ext_depth(inode))
		goal = ext4_idx_pblock(EXT_FIRST_INDEX(ext_inode_hdr(inode)));
	else
		goal = ext4_inode_to_goal_block(inode);

	newblock = ext4_new_meta_blocks(inode, goal, flags,
					NULL, &err);
	if (newblock == 0)
		return err;

	bh = fs_bwrite(inode->i_sb, newblock, &err);
	if (!bh) {
		ext4_ext_free_blocks(inode, newblock, 1, 0);
		return err;
	}

	/* move top-level index/leaf into new block */
	memmove(bh->b_data, inode->i_data, sizeof(inode->i_data));

	/* set size of new block */
	neh = ext_block_hdr(bh);
	/* old root could have indexes or leaves
	 * so calculate e_max right way */
	if (ext_depth(inode))
		neh->eh_max = cpu_to_le16(ext4_ext_space_block_idx(inode, 0));
	else
		neh->eh_max = cpu_to_le16(ext4_ext_space_block(inode, 0));

	neh->eh_magic = cpu_to_le16(EXT4_EXT_MAGIC);
	ext4_extent_block_csum_set(inode, neh);

	/* Update top-level index: num,max,pointer */
	neh = ext_inode_hdr(inode);
	neh->eh_entries = cpu_to_le16(1);
	ext4_idx_store_pblock(EXT_FIRST_INDEX(neh), newblock);
	if (neh->eh_depth == 0) {
		/* Root extent block becomes index block */
		neh->eh_max = cpu_to_le16(ext4_ext_space_root_idx(inode, 0));
		EXT_FIRST_INDEX(neh)->ei_block =
			EXT_FIRST_EXTENT(neh)->ee_block;
	}
	le16_add_cpu(&neh->eh_depth, 1);

	fs_mark_buffer_dirty(bh);
	ext4_mark_inode_dirty(inode);
	fs_brelse(bh);

	return err;
}

void print_path(struct ext4_ext_path *path)
{
	int i = path->p_depth;
	printf("====================\n");
	while (i >= 0) {
		printf("depth %d, p_block: %llu, p_ext offset: %d, p_idx offset: %d\n", i,
			path->p_block,
			(path->p_ext)?(path->p_ext - EXT_FIRST_EXTENT(path->p_hdr)):0,
			(path->p_idx)?(path->p_idx - EXT_FIRST_INDEX(path->p_hdr)):0);
		i--;
		path++;
	}
}

static inline int
ext4_ext_replace_path(struct ext4_ext_path *path,
		      struct ext_split_trans *spt,
		      int depth,
		      int level)
{
	int i = depth - level;

	ext4_ext_drop_refs(path + i, 1);
	path[i] = spt->path;
}

int ext4_ext_insert_extent(struct inode *inode, struct ext4_ext_path **ppath, struct ext4_extent *newext)
{
	int i, depth, level, ret = 0;
	ext4_fsblk_t ptr = 0;
	struct ext4_ext_path *path = *ppath;
	struct ext_split_trans *spt = NULL, newblock = {0};

	depth = ext_depth(inode);
	for (i = depth, level = 0;i >= 0;i--, level++)
		if (EXT_HAS_FREE_INDEX(path + i))
			break;

	if (level) {
		spt = kzalloc(sizeof(struct ext_split_trans) * (level),
				GFP_NOFS);
		if (!spt) {
			ret = -ENOMEM;
			goto out;
		}
	}
	i = 0;
again:
	depth = ext_depth(inode);

	do {
		if (!i) {
			ret = ext4_ext_insert_leaf(inode, path, depth - i,
					     newext, &newblock);
		} else {
			ret = ext4_ext_insert_index(inode, path, depth - i,
					     newext, ext4_ext_block_index(spt[i-1].path.p_hdr),
					     spt[i-1].ptr,
					     &newblock);
		}
		ptr = newblock.ptr;

		if (ret && ret != EXT_INODE_HDR_NEED_GROW)
			goto out;
		else if (spt && ptr && !ret) {
			/* Prepare for the next iteration after splitting. */
			spt[i] = newblock;
		}

		i++;
	} while (ptr != 0 && i <= depth);
	
	if (ret == EXT_INODE_HDR_NEED_GROW) {
		ret = ext4_ext_grow_indepth(inode, 0);
		if (ret)
			goto out;
		ret = ext4_find_extent(inode, le32_to_cpu(newext->ee_block), ppath, 0);
		if (ret)
			goto out;
		i = depth;
		path = *ppath;
		goto again;
	}
out:
	if (ret) {
		if (path)
			ext4_ext_drop_refs(path, 0);

		while (--level >= 0 && spt) {
			if (spt[level].ptr) {
				ext4_ext_free_blocks(inode, spt[level].ptr, 1, 0);
				ext4_ext_drop_refs(&spt[level].path, 1);
			}
		}
	} else {
		while (--level >= 0 && spt) {
			struct ext4_extent_header *eh;
			if (spt[level].switch_to)
				ext4_ext_replace_path(path,
						      spt,
						      depth,
						      level);
			else if (spt[level].ptr)
				ext4_ext_drop_refs(&spt[level].path, 1);

		}
	}
	if (spt)
		kfree(spt);
	return ret;
}

static void ext4_ext_remove_blocks(struct inode *inode, struct ext4_extent *ex,
				ext4_lblk_t from, ext4_lblk_t to)
{
	int len = to - from + 1;
	ext4_lblk_t num;
	ext4_fsblk_t start;
	num = from - le32_to_cpu(ex->ee_block);
	start = ext4_ext_pblock(ex) + num;
	ext_debug("Freeing %lu at %llu, %d\n", from, start, len);
	ext4_ext_free_blocks(inode, start, len, 0);
}

static int ext4_ext_remove_idx(struct inode *inode, struct ext4_ext_path *path, int depth)
{
	int err, i = depth;
	ext4_fsblk_t leaf;

	/* free index block */
	leaf = ext4_idx_pblock(path[i].p_idx);

	if (path[i].p_idx != EXT_LAST_INDEX(path[i].p_hdr)) {
		int len = EXT_LAST_INDEX(path[i].p_hdr) - path[i].p_idx;
		memmove(path[i].p_idx, path[i].p_idx + 1,
			len * sizeof(struct ext4_extent_idx));
	}

	le16_add_cpu(&path[i].p_hdr->eh_entries, -1);
	err = __ext4_ext_dirty(inode, path + i);
	if (err)
		return err;

	ext_debug("IDX: Freeing %lu at %llu, %d\n",
		le32_to_cpu(path[i].p_idx->ei_block), leaf, 1);
	ext4_ext_free_blocks(inode, leaf, 1, 0);

	while (i > 0) {
		if (path[i].p_idx != EXT_FIRST_INDEX(path[i].p_hdr))
			break;

		path[i-1].p_idx->ei_block = path[i].p_idx->ei_block;
		err = __ext4_ext_dirty(inode, path + i - 1);
		if (err)
			break;

		i--;
	}
	return err;
}

static int ext4_ext_remove_leaf(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t from, ext4_lblk_t to)
{
	
	int depth = ext_depth(inode);
	struct ext4_extent *ex = path[depth].p_ext;
	struct ext4_extent *start_ex, *ex2 = NULL;
	struct ext4_extent_header *eh = path[depth].p_hdr;
	int len, err = 0, new_entries;

	start_ex = ex;
	new_entries = le16_to_cpu(eh->eh_entries);
	while (ex <= EXT_LAST_EXTENT(path[depth].p_hdr)
		&& le32_to_cpu(ex->ee_block) <= to) {
		int new_len = 0;
		int unwritten;
		ext4_fsblk_t start, new_start;
		new_start = start = le32_to_cpu(ex->ee_block);
		len = ext4_ext_get_actual_len(ex);
		if (start < from) {
			start = from;
			len -= from - start;
			new_len = from - start;
			start_ex++;
		}
		if (start + len - 1 > to) {
			len -= start + len - 1 - to;
			new_len = start + len - 1 - to;
			new_start += to + 1;
			ex2 = ex;
		}

		ext4_ext_remove_blocks(inode, ex, start, start + len - 1);
		ex->ee_block = cpu_to_le32(new_start);
		if (!new_len)
			new_entries--;
		else {
			unwritten = ext4_ext_is_unwritten(ex);
			ex->ee_len = cpu_to_le16(new_len);
			if (unwritten)
				ext4_ext_mark_unwritten(ex);

		}

		ex += 1;
	}

	if (ex2 == NULL)
		ex2 = ex;

	if (ex2 <= EXT_LAST_EXTENT(eh))
		memmove(start_ex, ex2, EXT_LAST_EXTENT(eh) - ex2 + 1);

	eh->eh_entries = cpu_to_le16(new_entries);
	__ext4_ext_dirty(inode, path + depth);
	if (path[depth].p_ext == EXT_FIRST_EXTENT(eh)
		&& eh->eh_entries)
		err = ext4_ext_correct_indexes(inode, path);

	/* if this leaf is free, then we should
	 * remove it from index block above */
	if (err == 0 && eh->eh_entries == 0 && path[depth].p_bh != NULL)
		err = ext4_ext_remove_idx(inode, path, depth - 1);

	return err;
}

static int inline
ext4_ext_more_to_rm(struct ext4_ext_path *path, ext4_lblk_t to)
{
	if (!le16_to_cpu(path->p_hdr->eh_entries))
		return 0;

	if (path->p_idx > EXT_LAST_INDEX(path->p_hdr))
		return 0;

	if (le32_to_cpu(path->p_idx->ei_block) > to)
		return 0;

	return 1;
}

int ext4_ext_remove_space(struct inode *inode, ext4_lblk_t from, ext4_lblk_t to)
{
	struct ext4_ext_path *path = NULL;
	int ret, depth = ext_depth(inode), i;

	ret = ext4_find_extent(inode, from, &path, 0);
	if (ret)
		goto out;

	if (!path[depth].p_ext ||
		!in_range(from, le32_to_cpu(path[depth].p_ext->ee_block),
			 ext4_ext_get_actual_len(path[depth].p_ext))) {
		ret = 0;
		goto out;
	}

	i = depth;
	while (i >= 0) {
		if (i == depth) {
			struct ext4_extent_header *eh;
			struct ext4_extent *first_ex, *last_ex;
			ext4_lblk_t leaf_from, leaf_to;
			eh = path[i].p_hdr;
			assert(le16_to_cpu(eh->eh_entries) > 0);
			first_ex = EXT_FIRST_EXTENT(eh);
			last_ex = EXT_LAST_EXTENT(eh);
			leaf_from = le32_to_cpu(first_ex->ee_block);
			leaf_to = le32_to_cpu(last_ex->ee_block)
				   + ext4_ext_get_actual_len(last_ex) - 1;
			if (leaf_from < from)
				leaf_from = from;

			if (leaf_to > to)
				leaf_to = to;

			ext4_ext_remove_leaf(inode, path, leaf_from, leaf_to);
			ext4_ext_drop_refs(path + i, 0);
			i--;
			continue;
		} else {
			struct ext4_extent_header *eh;
			eh = path[i].p_hdr;
			if (ext4_ext_more_to_rm(path + i, to)) {
				struct buffer_head *bh;
				if (path[i+1].p_bh)
					ext4_ext_drop_refs(path + i + 1, 0);

				bh = read_extent_tree_block(inode,
					ext4_idx_pblock(path[i].p_idx),
					depth - i - 1, &ret, 0);
				if (ret)
					goto out;

				path[i].p_block = ext4_idx_pblock(path[i].p_idx);
				path[i+1].p_bh = bh;
				path[i+1].p_hdr = ext_block_hdr(bh);
				path[i+1].p_depth = depth - i - 1;
				if (i + 1 == depth)
					path[i+1].p_ext = EXT_FIRST_EXTENT(path[i+1].p_hdr);
				else
					path[i+1].p_idx = EXT_FIRST_INDEX(path[i+1].p_hdr);

				i++;
			} else {
				if (!le16_to_cpu(eh->eh_entries) && i > 0) {
					
					ret = ext4_ext_remove_idx(inode, path, i - 1);
				}
				if (i) {
					fs_brelse(path[i].p_bh);
					path[i].p_bh = NULL;
				}
				i--;
			}
		}
	}

	/* TODO: flexible tree reduction should be here */
	if (path->p_depth) {
		int nr_entries = 0;
	}
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		ext_inode_hdr(inode)->eh_depth = 0;
		ext_inode_hdr(inode)->eh_max =
			cpu_to_le16(ext4_ext_space_root(inode, 0));
		ret = __ext4_ext_dirty(inode, path);
	}

out:
	ext4_ext_drop_refs(path, 0);
	kfree(path);
	path = NULL;
	return ret;
}

int ext4_ext_split_extent_at(struct inode *inode,
			     struct ext4_ext_path **ppath,
			     ext4_lblk_t split,
			     int split_flag,
			     int flags)
{
	struct ext4_extent *ex, newex;
	ext4_fsblk_t newblock;
	ext4_lblk_t ee_block;
	int ee_len;
	int depth = ext_depth(inode);
	int err = 0;

	ex = (*ppath)[depth].p_ext;
	ee_block = le32_to_cpu(ex->ee_block);
	ee_len = ext4_ext_get_actual_len(ex);
	newblock = split - ee_block + ext4_ext_pblock(ex);
	
	if (split == ee_block) {
		/*
		 * case b: block @split is the block that the extent begins with
		 * then we just change the state of the extent, and splitting
		 * is not needed.
		 */
		if (split_flag & EXT4_EXT_MARK_UNWRIT2)
			ext4_ext_mark_unwritten(ex);
		else
			ext4_ext_mark_initialized(ex);

		err = __ext4_ext_dirty(inode, *ppath + depth);
		goto out;
	}

	ex->ee_len = cpu_to_le16(split - ee_block);
	if (split_flag & EXT4_EXT_MARK_UNWRIT1)
		ext4_ext_mark_unwritten(ex);

	err = __ext4_ext_dirty(inode, *ppath + depth);
	if (err)
		goto out;

	newex.ee_block = cpu_to_le32(split);
	newex.ee_len   = cpu_to_le16(ee_len - (split - ee_block));
	ext4_ext_store_pblock(&newex, newblock);
	if (split_flag & EXT4_EXT_MARK_UNWRIT2)
		ext4_ext_mark_unwritten(&newex);
	err = ext4_ext_insert_extent(inode, ppath, &newex);
	if (err)
		goto restore_extent_len;

out:
	return err;
restore_extent_len:
	ex->ee_len = cpu_to_le16(ee_len);
	err = __ext4_ext_dirty(inode, *ppath + depth);
	return err;
}

static int ext4_ext_convert_to_initialized (
		struct inode *inode,
		struct ext4_ext_path **ppath,
		ext4_lblk_t split,
		unsigned long blocks,
		int flags)
{
	int depth = ext_depth(inode), err;
	struct ext4_extent *ex = (*ppath)[depth].p_ext;

	assert (le32_to_cpu(ex->ee_block) <= split);

	if (split + blocks == le32_to_cpu(ex->ee_block)
				+ ext4_ext_get_actual_len(ex)) {
		/* split and initialize right part */
		err = ext4_ext_split_extent_at(inode, ppath, split,
				EXT4_EXT_MARK_UNWRIT1, flags);
	} else if (le32_to_cpu(ex->ee_block) == split) {
		/* split and initialize left part */
		err = ext4_ext_split_extent_at(inode, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT2, flags);
	} else {
		/* split 1 extent to 3 and initialize the 2nd */
		err = ext4_ext_split_extent_at(inode, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2, flags);
		if (!err) {
			err = ext4_ext_split_extent_at(inode, ppath, split,
					EXT4_EXT_MARK_UNWRIT1, flags);
		}
	}

	return err;
}

int ext4_ext_tree_init(void *v, struct inode *inode)
{
	struct ext4_extent_header *eh;

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = cpu_to_le16(EXT4_EXT_MAGIC);
	eh->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
	ext4_mark_inode_dirty(inode);
	return 0;
}

/*
 * ext4_ext_next_allocated_block:
 * returns allocated block in subsequent extent or EXT_MAX_BLOCKS.
 * NOTE: it considers block number from index entry as
 * allocated block. Thus, index entries have to be consistent
 * with leaves.
 */
#define EXT_MAX_BLOCKS (ext4_lblk_t)-1

ext4_lblk_t
ext4_ext_next_allocated_block(struct ext4_ext_path *path)
{
	int depth;

	depth = path->p_depth;

	if (depth == 0 && path->p_ext == NULL)
		return EXT_MAX_BLOCKS;

	while (depth >= 0) {
		if (depth == path->p_depth) {
			/* leaf */
			if (path[depth].p_ext &&
				path[depth].p_ext !=
					EXT_LAST_EXTENT(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_ext[1].ee_block);
		} else {
			/* index */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return le32_to_cpu(path[depth].p_idx[1].ei_block);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

int ext4_ext_get_blocks(void *handle, struct inode *inode, ext4_fsblk_t iblock,
			unsigned long max_blocks, struct buffer_head *bh_result,
			int create, int extend_disksize)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex;
	int goal, err = 0, depth;
	unsigned long allocated = 0;
	ext4_fsblk_t next, newblock;

	clear_buffer_new(bh_result);

	/* find extent for this block */
	err = ext4_find_extent(inode, iblock, &path, 0);
	if (err) {
		path = NULL;
		goto out2;
	}

	depth = ext_depth(inode);

	/*
	 * consistent leaf must not be empty
	 * this situations is possible, though, _during_ tree modification
	 * this is why assert can't be put in ext4_ext_find_extent()
	 */
	if ((ex = path[depth].p_ext)) {
	        ext4_lblk_t ee_block = le32_to_cpu(ex->ee_block);
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		unsigned int ee_len  = ext4_ext_get_actual_len(ex);
		/* if found exent covers block, simple return it */
	        if (in_range(iblock, ee_block, ee_len)) {
			newblock = iblock - ee_block + ee_start;
			/* number of remain blocks in the extent */
			allocated = ee_len - (iblock - ee_block);
			goto out;
		}
	}

	/*
	 * requested block isn't allocated yet
	 * we couldn't try to create block if create flag is zero
	 */
	if (!create) {
		goto out2;
	}

	/* find next allocated block so that we know how many
	 * blocks we can allocate without ovelapping next extent */
	next = ext4_ext_next_allocated_block(path);
	allocated = next - iblock;
	if (allocated > max_blocks)
		allocated = max_blocks;

	/* allocate new block */
	goal = ext4_ext_find_goal(inode, path, iblock);
	newblock = ext4_new_meta_blocks(inode, goal, 0,
					&allocated, &err);
	if (!newblock)
		goto out2;

	/* try to insert new extent into found leaf and return */
	newex.ee_block = cpu_to_le32(iblock);
	ext4_ext_store_pblock(&newex, newblock);
	newex.ee_len = cpu_to_le16(allocated);
	err = ext4_ext_insert_extent(inode, &path, &newex);
	if (err) {
		/* free data blocks we just allocated */
		ext4_ext_free_blocks(inode, ext4_ext_pblock(&newex),
				le16_to_cpu(newex.ee_len), 0);
		goto out2;
	}
	print_path(path);

	/* previous routine could use block we allocated */
	newblock = ext4_ext_pblock(&newex);
	set_buffer_new(bh_result);

out:
	if (allocated > max_blocks)
		allocated = max_blocks;
	set_buffer_mapped(bh_result);
	bh_result->b_bdev = inode->i_sb->s_bdev;
	bh_result->b_blocknr = newblock;
out2:
	if (path) {
		ext4_ext_drop_refs(path, 0);
		kfree(path);
	}

	return err ? err : allocated;
}
