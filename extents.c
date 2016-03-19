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
#define EXT4_EXT_NO_COMBINE	0x20 /* do not combine two extents */

#define _EXTENTS_TEST

#ifdef _EXTENTS_TEST
#define AGGRESSIVE_TEST

static inline int ext4_mark_inode_dirty(struct inode *inode)
{
	inode->i_data_dirty = 1;
	return 0;
}

#define ext4_inode_to_goal_block(inode) ({ UNUSED(inode); 0;})

static inline int ext4_allocate_single_block(struct inode *inode,
					     ext4_fsblk_t fake,
					     ext4_fsblk_t *blockp,
					     ext4_lblk_t count)
{
	int err;
	UNUSED(fake);
	UNUSED(count);

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
			ext4_lblk_t *count, int *errp)
{
	ext4_fsblk_t block = 0;
	ext4_lblk_t nrblocks = (count)?(*count):1;
	UNUSED(flags);

	*errp = ext4_allocate_single_block(inode, goal, &block, nrblocks);
	if (count)
		*count = 1;
	return block;
}

static void ext4_ext_free_blocks(struct inode *inode,
				 ext4_fsblk_t block,
				 int count, int flags)
{
	UNUSED(flags);
	bitmap_bits_free(inode->i_db->db_bitmap, block, count);
}

#define ext_debug printf
#endif

void ext4_ext_drop_refs(struct ext4_ext_path *path, int keep_other);

static struct ext4_ext_path *
ext4_ext_alloc_path(struct inode *inode,
		    struct ext4_ext_path **orig_path)
{
	int depth = ext_depth(inode);
	int path_depth = depth + 1;
	struct ext4_ext_path *path = (orig_path)?(*orig_path):NULL;

	if (path) {
		if (depth > path[0].p_maxdepth) {
			ext4_ext_drop_refs(path, 0);
			xfree(path);
			*orig_path = NULL;
		} else {
			ext4_ext_drop_refs(path, 0);
			return path;
		}
	}

	/* account possible depth increase */
	path = xzalloc(sizeof(struct ext4_ext_path) *
			(path_depth + 1));
	if (!path)
		return NULL;

	path[0].p_maxdepth = path_depth;
	return path;
}

static void ext4_ext_free_path(struct ext4_ext_path *path)
{
	ext4_ext_drop_refs(path, 0);
	xfree(path);
}

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
			ext4_lblk_t ext_block = ext4_ext_lblock(ex);

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

	goal = ext4_ext_find_goal(inode, path, ext4_ext_lblock(ex));
	newblock = ext4_new_meta_blocks(inode, goal, flags,
					NULL, err);
	return newblock;
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
	tail->et_checksum = cpu_to_le32(ext4_ext_block_csum(
			inode, eh));
}

static int __ext4_ext_dirty(struct inode *inode,
		      struct ext4_ext_path *path)
{
	int err;

	if (path->p_bh) {
		ext4_extent_block_csum_set(inode, ext_block_hdr(path->p_bh));
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

	for (i = 0; i <= depth; i++, path++) {
		if (path->p_bh) {
			fs_brelse(path->p_bh);
			path->p_bh = NULL;
		}
	}
}

/*
 * Check that whether the basic information inside the extent header
 * is correct or not.
 */
static int ext4_ext_check(struct inode *inode,
			    struct ext4_extent_header *eh, uint16_t  depth,
			    ext4_fsblk_t pblk)
{
	struct ext4_extent_tail *tail;
	const char *error_msg = NULL;
	UNUSED(pblk);

	if (eh->eh_magic != cpu_to_le16(EXT4_EXT_MAGIC)) {
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
	if (tail->et_checksum != cpu_to_le32(ext4_ext_block_csum(inode, eh))) {
		/* FIXME: Warning: extent checksum damaged? */
	}

	return 0;

corrupted:
	ext_debug("ext4_check_header: %s\n", error_msg);
	return -EIO;
}

static struct buffer_head *
read_extent_tree_block(struct inode *inode, ext4_fsblk_t pblk, int depth,
			 int *perr, int flags)
{
	struct buffer_head		*bh;
	int				err;
	UNUSED(flags);

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
ext4_ext_binsearch_idx(struct ext4_ext_path *path, ext4_lblk_t block)
{
	struct ext4_extent_header *eh = path->p_hdr;
	struct ext4_extent_idx *r, *l, *m;

	l = EXT_FIRST_INDEX(eh) + 1;
	r = EXT_LAST_INDEX(eh);
	while (l <= r) {
		m = l + (r - l) / 2;
		if (block < ext4_idx_lblock(m))
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
ext4_ext_binsearch(struct ext4_ext_path *path, ext4_lblk_t block)
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
		if (block < ext4_ext_lblock(m))
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

int ext4_find_extent(struct inode *inode, ext4_lblk_t block,
		 struct ext4_ext_path **orig_path, int flags)
{
	struct ext4_extent_header *eh;
	struct buffer_head *bh;
	ext4_fsblk_t buf_block = 0;
	struct ext4_ext_path *path;
	int depth, i, ppos = 0;
	int ret;

	eh = ext_inode_hdr(inode);
	depth = ext_depth(inode);

	path = ext4_ext_alloc_path(inode, orig_path);
	if (!path)
		return -ENOMEM;

	path[0].p_hdr = eh;
	path[0].p_bh = NULL;

	i = depth;
	/* walk through the tree */
	while (i) {
		ext4_ext_binsearch_idx(path + ppos, block);
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
	ext4_ext_binsearch(path + ppos, block);
	/* if not an empty leaf */
	if (path[ppos].p_ext)
		path[ppos].p_block = ext4_ext_pblock(path[ppos].p_ext);

	*orig_path = path;

	ret = 0;
	return ret;

err:
	ext4_ext_free_path(path);
	if (orig_path)
		*orig_path = NULL;
	return ret;
}

static void ext4_ext_init_header(struct inode *inode, struct ext4_extent_header *eh, int depth)
{
	eh->eh_entries = 0;
	eh->eh_max = cpu_to_le16(ext4_ext_max_entries(inode, depth, 0));
	eh->eh_magic = cpu_to_le16(EXT4_EXT_MAGIC);
	eh->eh_depth = cpu_to_le16(depth);
}

static int ext4_ext_insert_index(struct inode *inode,
				 struct ext4_ext_path *path,
				 int at,
				 ext4_lblk_t insert_index,
				 ext4_fsblk_t insert_block,
				 bool set_to_ix)
{
	struct ext4_extent_idx *ix;
	struct ext4_ext_path *curp = path + at;
	int len, err;
	struct ext4_extent_header *eh;

	if (curp->p_idx && insert_index == ext4_idx_lblock(curp->p_idx))
		return -EIO;

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max))
		return -EIO;

	eh = curp->p_hdr;
	if (curp->p_idx == NULL) {
		ix = EXT_FIRST_INDEX(eh);
		curp->p_idx = ix;
	} else if (insert_index > ext4_idx_lblock(curp->p_idx)) {
		/* insert after */
		ix = curp->p_idx + 1;
	} else {
		/* insert before */
		ix = curp->p_idx;
	}

	if (ix > EXT_MAX_INDEX(eh))
		return -EIO;

	len = EXT_LAST_INDEX(eh) - ix + 1;
	assert(len >= 0);
	if (len > 0)
		memmove(ix + 1, ix, len * sizeof(struct ext4_extent_idx));

	ext4_idx_store_lblock(ix, insert_index);
	ext4_idx_store_pblock(ix, insert_block);
	le16_add_cpu(&eh->eh_entries, 1);

	if (ix > EXT_LAST_INDEX(eh)) {
		err = -EIO;
		goto out;
	}

	err = __ext4_ext_dirty(inode, curp);

out:
	if (!err && set_to_ix) {
		curp->p_idx = ix;
		curp->p_block = ext4_idx_pblock(ix);
	}
	return err;
}

static int ext4_ext_split_node(struct inode *inode,
			       struct ext4_ext_path *path,
			       int at,
			       struct ext4_extent *newext)
{
	int i, ret;
	ext4_fsblk_t *newblocks = NULL;
	int depth = ext_depth(inode);
	int nblocks = depth - at + 1;

	assert(at > 0);
	newblocks = xzalloc(sizeof(ext4_fsblk_t) * nblocks);
	if (!newblocks) {
		ret = -ENOMEM;
		goto cleanup;
	}

	for (i = 0;i < nblocks;i++) {
		newblocks[i] = ext4_ext_new_meta_block(inode, path,
				newext, &ret, 0);
		if (ret)
			goto cleanup;
	}

	for (i = at;i <= depth;i++) {
		int mid, max, rem, curr;
		ext4_lblk_t insert_index;
		struct buffer_head *bh = NULL;

		/*  For write access.*/
		bh = fs_bwrite(inode->i_sb, newblocks[i - at], &ret);
		if (!bh)
			goto cleanup;

		max = le16_to_cpu(path[i].p_hdr->eh_max);
		mid = max / 2;
		rem = max - mid;
		curr = (i == depth)
			?(path[i].p_ext - EXT_FIRST_EXTENT(path[i].p_hdr))
			:(path[i].p_idx - EXT_FIRST_INDEX(path[i].p_hdr));

		if (i == depth) {
			/* start copy from next extent */
			struct ext4_extent_header *eh, *neh;
			struct ext4_extent *ex, *nex;
			eh = path[i].p_hdr;
			neh = ext_block_hdr(bh);
			ex = EXT_FIRST_EXTENT(eh);
			nex = EXT_FIRST_EXTENT(neh);
			ext4_ext_init_header(inode, neh, 0);
			if (mid) {
				memcpy(nex, ex + mid,
					sizeof(struct ext4_extent) * rem);
				le16_add_cpu(&neh->eh_entries, rem);
				le16_add_cpu(&path[i].p_hdr->eh_entries, -rem);
				ret = __ext4_ext_dirty(inode, path + i);
				if (ret)
					goto cleanup;

			}

			fs_mark_buffer_dirty(bh);
			insert_index = ext4_ext_lblock(nex);

			if (curr >= mid) {
				fs_brelse(path[i].p_bh);
				path[i].p_ext = EXT_FIRST_EXTENT(neh) + curr - mid;
				path[i].p_hdr = neh;
				path[i].p_bh = bh;
			} else
				fs_brelse(bh);

		} else {
			struct ext4_extent_header *eh, *neh;
			struct ext4_extent_idx *ix, *nix;
			eh = path[i].p_hdr;
			neh = ext_block_hdr(bh);
			ix = EXT_FIRST_INDEX(eh);
			nix = EXT_FIRST_INDEX(neh);
			ext4_ext_init_header(inode, neh, depth - i);
			if (mid) {
				memcpy(nix, ix + mid,
					sizeof(struct ext4_extent) * rem);
				le16_add_cpu(&neh->eh_entries, rem);
				le16_add_cpu(&path[i].p_hdr->eh_entries, -rem);
				ret = __ext4_ext_dirty(inode, path + i);
				if (ret)
					goto cleanup;

			}

			fs_mark_buffer_dirty(bh);
			insert_index = ext4_idx_lblock(nix);

			if (curr >= mid) {
				fs_brelse(path[i].p_bh);
				path[i].p_idx = EXT_FIRST_INDEX(neh) + curr - mid;
				path[i].p_hdr = neh;
				path[i].p_bh = bh;
			} else
				fs_brelse(bh);

		}

		ret = ext4_ext_insert_index(inode, path, i - 1,
				insert_index,
				newblocks[i - at],
				curr >= mid);
		if (ret)
			break;
	}

cleanup:
	if (ret) {
		for (i = 0;i < nblocks;i++) {
			if (newblocks[i])
				ext4_ext_free_blocks(inode, newblocks[i], 1, 0);

		}
	}
	if (newblocks)
		xfree(newblocks);

	return ret;
}

/*
 * ext4_ext_correct_indexes:
 * if leaf/node gets modified and modified extent/index
 * is first in the leaf/node,
 * then we have to correct all indexes above.
 */
static int ext4_ext_correct_indexes(struct inode *inode,
				    struct ext4_ext_path *path,
				    int at)
{
	struct ext4_extent_header *eh;
	int depth = ext_depth(inode);
	struct ext4_extent *ex;
	__le32 border;
	int k, err = 0;

	assert(at >= 0);
	if (!at)
		return 0;

	if (depth == at) {
		eh = path[at].p_hdr;
		ex = path[at].p_ext;

		if (ex == NULL || eh == NULL)
			return -EIO;

		if (at == 0) {
			/* there is no tree at all */
			return 0;
		}

		if (ex != EXT_FIRST_EXTENT(eh)) {
			/* we correct tree if first leaf got modified only */
			return 0;
		}

		k = at - 1;
		border = path[at].p_ext->ee_block;
		path[k].p_idx->ei_block = border;
		err = __ext4_ext_dirty(inode, path + k);
		if (err)
			return err;

	} else
		k = at;

	while (k) {
		/* change all left-side indexes */
		if (path[k].p_idx != EXT_FIRST_INDEX(path[k].p_hdr))
			break;
		path[k-1].p_idx->ei_block = border;
		err = __ext4_ext_dirty(inode, path + k-1);
		if (err)
			break;

		k--;
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

	if (ext4_ext_lblock(ex2) + ext4_ext_get_actual_len(ex2) !=
			ext4_ext_lblock(ex1))
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

	if (ext4_ext_lblock(ex1) + ext4_ext_get_actual_len(ex1) !=
			ext4_ext_lblock(ex2))
		return 0;

	return 1;
}

#define EXT_INODE_HDR_NEED_GROW 0x1

static int ext4_ext_insert_leaf(struct inode *inode,
				struct ext4_ext_path *path,
				int at,
				struct ext4_extent *newext,
				int flags)
{
	struct ext4_ext_path *curp = path + at;
	struct ext4_extent *ex = curp->p_ext;
	int len, err, unwritten;
	struct ext4_extent_header *eh;

	if (curp->p_ext && ext4_ext_lblock(newext) == ext4_ext_lblock(curp->p_ext))
		return -EIO;

	if (!(flags & EXT4_EXT_NO_COMBINE)) {
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
	}

	if (le16_to_cpu(curp->p_hdr->eh_entries)
			     == le16_to_cpu(curp->p_hdr->eh_max)) {
		err = EXT_INODE_HDR_NEED_GROW;
		goto out;
	} else {
		eh = curp->p_hdr;
		if (curp->p_ext == NULL) {
			ex = EXT_FIRST_EXTENT(eh);
			curp->p_ext = ex;
		} else if (ext4_ext_lblock(newext) > ext4_ext_lblock(curp->p_ext)) {
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

	err = ext4_ext_correct_indexes(inode, path, at);
	if (err)
		goto out;
	err = __ext4_ext_dirty(inode, curp);

out:
	if (!err) {
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
	ext_debug("====================\n");
	while (i >= 0) {
		ext_debug("depth: %" PRIu32 ", p_block: %" PRIu64 ", p_ext offset: %td, p_idx offset: %td\n", i,
			  path->p_block,
			  (path->p_ext)?(path->p_ext - EXT_FIRST_EXTENT(path->p_hdr)):0,
			  (path->p_idx)?(path->p_idx - EXT_FIRST_INDEX(path->p_hdr)):0);
		i--;
		path++;
	}
}


int ext4_ext_insert_extent(struct inode *inode, struct ext4_ext_path **ppath, struct ext4_extent *newext, int flags)
{
	int depth, level, ret = 0;
	struct ext4_ext_path *path = *ppath;

again:
	depth = ext_depth(inode);
	ret = ext4_ext_insert_leaf(inode, path, depth,
				   newext,
				   flags);
	if (ret == EXT_INODE_HDR_NEED_GROW) {
		int i;
		for (i = depth, level = 0;i >= 0;i--, level++)
			if (EXT_HAS_FREE_INDEX(path + i))
				break;

		/* Do we need to grow the tree? */
		if (i < 0) {
			ret = ext4_ext_grow_indepth(inode, 0);
			if (ret)
				goto out;

			ret = ext4_find_extent(inode, ext4_ext_lblock(newext), ppath, 0);
			if (ret)
				goto out;

			path = *ppath;
			/*
			 * After growing the tree, there should be free space in
			 * the only child node of the root.
			 */
			level--;
			depth++;
		}

		i = depth - (level - 1);

		/* We split from leaf to the i-th node */
		if (level > 0) {
			ret = ext4_ext_split_node(inode, path, i,
						  newext);
			if (ret)
				goto out;

		}
		goto again;
	}

out:
	return ret;
}

static void ext4_ext_remove_blocks(struct inode *inode, struct ext4_extent *ex,
				ext4_lblk_t from, ext4_lblk_t to)
{
	int len = to - from + 1;
	ext4_lblk_t num;
	ext4_fsblk_t start;
	num = from - ext4_ext_lblock(ex);
	start = ext4_ext_pblock(ex) + num;
	ext_debug("Freeing %" PRIu32 " at %" PRIu64 ", %d\n", from, start, len);
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

	ext_debug("IDX: Freeing %" PRIu32 " at %" PRIu64 ", %d\n",
		ext4_idx_lblock(path[i].p_idx), leaf, 1);
	ext4_ext_free_blocks(inode, leaf, 1, 0);
	return err;
}

/*
 * NOTE: After removal, path should not be reused.
 */
int ext4_ext_remove_extent(struct inode *inode, struct ext4_ext_path *path)
{
	int len;
	int err = 0;
	ext4_lblk_t start;
	uint16_t new_entries;
	int depth = ext_depth(inode);
	struct ext4_extent *ex = path[depth].p_ext,
			   *ex2 = ex + 1;
	struct ext4_extent_header *eh = path[depth].p_hdr;
	if (!ex)
		return -EINVAL;

	start = ext4_ext_lblock(ex);
	len = ext4_ext_get_actual_len(ex);
	new_entries = le16_to_cpu(eh->eh_entries) - 1;

	ext4_ext_remove_blocks(inode, ex, start, start + len - 1);
	if (ex2 <= EXT_LAST_EXTENT(eh))
		memmove(ex, ex2,
			(EXT_LAST_EXTENT(eh) - ex2 + 1) * sizeof(struct ext4_extent));
	eh->eh_entries = cpu_to_le16(new_entries);

	__ext4_ext_dirty(inode, path + depth);

	/*
	 * If the node is free, then we should
	 * remove it from index block above.
	 */
	while (depth > 0) {
		eh = path[depth].p_hdr;
		if (eh->eh_entries == 0 && path[depth].p_bh != NULL) {
			err = ext4_ext_remove_idx(inode, path, depth - 1);
			if (err)
				break;

			ext4_ext_drop_refs(path + depth, 1);
		} else
			break;

		depth--;
	}
	err = ext4_ext_correct_indexes(inode, path, depth);

	/* TODO: flexible tree reduction should be here */
	if (path->p_hdr->eh_entries == 0) {
		/*
		 * truncate to zero freed all the tree,
		 * so we need to correct eh_depth
		 */
		ext_inode_hdr(inode)->eh_depth = 0;
		ext_inode_hdr(inode)->eh_max =
			cpu_to_le16(ext4_ext_space_root(inode, 0));
		err = __ext4_ext_dirty(inode, path);
	}

	return err;
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
			  return ext4_ext_lblock(&path[depth].p_ext[1]);
		} else {
			/* index */
			if (path[depth].p_idx !=
					EXT_LAST_INDEX(path[depth].p_hdr))
			  return ext4_idx_lblock(&path[depth].p_idx[1]);
		}
		depth--;
	}

	return EXT_MAX_BLOCKS;
}

int ext4_ext_truncate(struct inode *inode,
		      ext4_lblk_t from, ext4_lblk_t to)
{
	int depth = ext_depth(inode), ret = -EIO;
	struct ext4_extent *ex;
	struct ext4_ext_path *path = NULL;
	ext4_lblk_t now = from;

	if (to < from)
		return -EINVAL;

	ret = ext4_find_extent(inode, from, &path, 0);
	if (ret < 0)
		goto out;

	ex = path[depth].p_ext;
	if (!ex)
		goto out;

	if (from < ext4_ext_lblock(ex) &&
	    to < ext4_ext_lblock(ex)) {
		ret = 0;
		goto out;
	}
	/* If we do remove_space inside the range of an extent */
	if ((ext4_ext_lblock(ex) < from) &&
	    (to < ext4_ext_lblock(ex) +
			ext4_ext_get_actual_len(ex) - 1)) {

		struct ext4_extent newex;
		int unwritten = ext4_ext_is_unwritten(ex);
		ext4_lblk_t ee_block = ext4_ext_lblock(ex);
		int32_t len = ext4_ext_get_actual_len(ex);
		ext4_fsblk_t newblock =
			to + 1 - ee_block + ext4_ext_pblock(ex);

		ex->ee_len = cpu_to_le16(from - ee_block);
		if (unwritten)
			ext4_ext_mark_unwritten(ex);

		__ext4_ext_dirty(inode, path + depth);

		ext4_ext_store_lblock(&newex, to + 1);
		newex.ee_len = cpu_to_le16(ee_block + len - 1 - to);
		ext4_ext_store_pblock(&newex, newblock);
		if (unwritten)
			ext4_ext_mark_unwritten(&newex);

		ret = ext4_ext_insert_extent(inode, &path, &newex, 0);
		goto out;
	}
	if (ext4_ext_lblock(ex) + ext4_ext_get_actual_len(ex) - 1 < from) {
		now = ext4_ext_next_allocated_block(path);
		ret = ext4_find_extent(inode, now, &path, 0);
		if (ret)
			goto out;

		ex = path[depth].p_ext;
	}
	while (ex &&
	       ext4_ext_lblock(ex) + ext4_ext_get_actual_len(ex) - 1 >= now &&
	       ext4_ext_lblock(ex) <= to) {
		int len, new_len = 0;
		int unwritten;
		ext4_lblk_t start, new_start;
		ext4_fsblk_t newblock;

		new_start = start = ext4_ext_lblock(ex);
		len = ext4_ext_get_actual_len(ex);
		newblock = ext4_ext_pblock(ex);
		if (start < from) {
			len -= from - start;
			new_len = from - start;
			start = from;
		} else {
			if (start + len - 1 > to) {
				new_len = start + len - 1 - to;
				len -= new_len;
				new_start = to + 1;
				newblock += to + 1 - start;
			}
		}

		now = ext4_ext_next_allocated_block(path);
		if (!new_len) {
			ret = ext4_ext_remove_extent(inode, path);
			if (ret)
				goto out;

		} else {
			ext4_ext_remove_blocks(inode,
				ex, start, start + len - 1);
			ext4_ext_store_lblock(ex, new_start);
			unwritten = ext4_ext_is_unwritten(ex);
			ex->ee_len = cpu_to_le16(new_len);
			ext4_ext_store_pblock(ex, newblock);
			if (unwritten)
				ext4_ext_mark_unwritten(ex);

			__ext4_ext_dirty(inode, path + depth);
		}
		ret = ext4_find_extent(inode, now, &path, 0);
		if (ret)
			goto out;

		depth = ext_depth(inode);
		ex = path[depth].p_ext;
	}
out:
	if (path)
		ext4_ext_free_path(path);

	return ret;
}

int ext4_ext_split_extent_at(struct inode *inode,
			     struct ext4_ext_path **ppath,
			     ext4_lblk_t split,
			     int split_flag)
{
	struct ext4_extent *ex, newex;
	ext4_fsblk_t newblock;
	ext4_lblk_t ee_block;
	int ee_len;
	int depth = ext_depth(inode);
	int err = 0;

	ex = (*ppath)[depth].p_ext;
	ee_block = ext4_ext_lblock(ex);
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

	ext4_ext_store_lblock(&newex, split);
	newex.ee_len   = cpu_to_le16(ee_len - (split - ee_block));
	ext4_ext_store_pblock(&newex, newblock);
	if (split_flag & EXT4_EXT_MARK_UNWRIT2)
		ext4_ext_mark_unwritten(&newex);
	err = ext4_ext_insert_extent(inode, ppath, &newex,
				EXT4_EXT_NO_COMBINE);
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
		unsigned long blocks)
{
	int depth = ext_depth(inode), err;
	struct ext4_extent *ex = (*ppath)[depth].p_ext;

	assert (ext4_ext_lblock(ex) <= split);

	if (split + blocks == ext4_ext_lblock(ex)
				+ ext4_ext_get_actual_len(ex)) {
		/* split and initialize right part */
		err = ext4_ext_split_extent_at(inode, ppath, split,
				EXT4_EXT_MARK_UNWRIT1);
	} else if (ext4_ext_lblock(ex) == split) {
		/* split and initialize left part */
		err = ext4_ext_split_extent_at(inode, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT2);
	} else {
		/* split 1 extent to 3 and initialize the 2nd */
		err = ext4_ext_split_extent_at(inode, ppath, split + blocks,
				EXT4_EXT_MARK_UNWRIT1 | EXT4_EXT_MARK_UNWRIT2);
		if (!err) {
			err = ext4_ext_split_extent_at(inode, ppath, split,
					EXT4_EXT_MARK_UNWRIT1);
		}
	}

	return err;
}

int ext4_ext_tree_init(void *v, struct inode *inode)
{
	struct ext4_extent_header *eh;
	UNUSED(v);

	eh = ext_inode_hdr(inode);
	eh->eh_depth = 0;
	eh->eh_entries = 0;
	eh->eh_magic = cpu_to_le16(EXT4_EXT_MAGIC);
	eh->eh_max = cpu_to_le16(ext4_ext_space_root(inode, 0));
	ext4_mark_inode_dirty(inode);
	return 0;
}

static int ext4_ext_zero_unwritten_range(struct inode *inode,
					 ext4_fsblk_t block,
					 unsigned long blocks_count)
{
	int err = 0;
	unsigned long i;
	int blocksize = inode->i_sb->s_blocksize;
	for (i = 0; i < blocks_count; i++) {
		struct buffer_head *bh;
		bh = fs_bwrite(inode->i_sb, block, &err);
		if (!bh)
			break;

		memset(bh->b_data, 0, blocksize);
		fs_mark_buffer_dirty(bh);
		fs_brelse(bh);
	}
	return err;
}

int ext4_ext_get_blocks(void *handle, struct inode *inode, ext4_lblk_t iblock,
			unsigned long max_blocks, struct buffer_head *bh_result,
			int create)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex;
	int goal, err = 0, depth;
	ext4_lblk_t allocated = 0;
	ext4_lblk_t next;
	ext4_fsblk_t newblock;
	UNUSED(handle);

	clear_buffer_new(bh_result);

	fs_start_trans(inode->i_sb);

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
	        ext4_lblk_t ee_block = ext4_ext_lblock(ex);
		ext4_fsblk_t ee_start = ext4_ext_pblock(ex);
		uint16_t ee_len  = ext4_ext_get_actual_len(ex);
		/* if found exent covers block, simple return it */
	        if (in_range(iblock, ee_block, ee_len)) {
			/* number of remain blocks in the extent */
			allocated = ee_len - (iblock - ee_block);

			if (ext4_ext_is_unwritten(ex)) {
				if (create) {
					unsigned long zero_range;
					zero_range = allocated;
					if (zero_range > max_blocks)
						zero_range = max_blocks;

					newblock = iblock - ee_block + ee_start;
					err = ext4_ext_zero_unwritten_range(
					    inode, newblock, zero_range);
					if (err)
						goto out2;

					err = ext4_ext_convert_to_initialized(
					    inode, &path, iblock,
					    zero_range);
					if (err)
						goto out2;

				} else {
					newblock = 0;
				}
			} else {
				newblock = iblock - ee_block + ee_start;
			}
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
	ext4_ext_store_lblock(&newex, iblock);
	ext4_ext_store_pblock(&newex, newblock);
	newex.ee_len = cpu_to_le16(allocated);
	err = ext4_ext_insert_extent(inode, &path, &newex, 0);
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
	if (path)
		ext4_ext_free_path(path);

	fs_stop_trans(inode->i_sb);

	return err ? err : (int)allocated;
}
