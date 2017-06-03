#include "ext4.h"
#include <malloc.h>
#include <memory.h>
#include <string.h>

#define _EXTENTS_TEST

#ifdef _EXTENTS_TEST
#define AGGRESSIVE_TEST

static inline int
ext4_mark_inode_dirty(struct inode *inode)
{
	inode->i_data_dirty = 1;
	return 0;
}

#define ext4_inode_to_goal_block(inode)                                        \
	({                                                                     \
		UNUSED(inode);                                                 \
		0;                                                             \
	})

static inline int
ext4_allocate_single_block(struct inode *inode, ext4_fsblk_t fake,
			   ext4_fsblk_t *blockp, ext4_lblk_t count)
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

static ext4_fsblk_t
ext4_new_meta_blocks(struct inode *inode, ext4_fsblk_t goal, unsigned int flags,
		     ext4_lblk_t *count, int *errp)
{
	ext4_fsblk_t block = 0;
	ext4_lblk_t nrblocks = (count) ? (*count) : 1;
	UNUSED(flags);

	*errp = ext4_allocate_single_block(inode, goal, &block, nrblocks);
	if (count)
		*count = 1;
	return block;
}

static void
ext4_ext_free_blocks(struct inode *inode, ext4_fsblk_t block, int count,
		     int flags)
{
	UNUSED(flags);
	bitmap_bits_free(inode->i_db->db_bitmap, block, count);
}

#define ext_debug print
#define ext4_assert assert

#endif

#if 1 /* WRAPPER */

#define printf_flush(...)                                                      \
	{                                                                      \
		fprintf(stderr, __VA_ARGS__);                                  \
		fflush(stderr);                                                \
	}
#define ext4_buf_blocknr(bcb) ((ext4_fsblk_t)(bcb)->b_blocknr)

#endif /* WRAPPER */

static void
extcursor_root_dirty(struct ext4_ext_cursor *cur);

static int
extcursor_alloc_block(struct ext4_ext_cursor *cur, ext4_fsblk_t *nblockp);

static int
extcursor_free_block(struct ext4_ext_cursor *cur, ext4_fsblk_t block);

typedef void (*extcursor_root_dirty_t)(struct ext4_ext_cursor *);
typedef int (*extcursor_alloc_block_t)(struct ext4_ext_cursor *,
				       ext4_fsblk_t *nblockp);
typedef int (*extcursor_free_block_t)(struct ext4_ext_cursor *,
				      ext4_fsblk_t block);

struct ext4_cursor_op {
	extcursor_root_dirty_t c_root_dirty_func;
	extcursor_alloc_block_t c_alloc_block_func;
	extcursor_free_block_t c_free_block_func;
} ext4_test_cursor_op = {.c_root_dirty_func = extcursor_root_dirty,
			 .c_alloc_block_func = extcursor_alloc_block,
			 .c_free_block_func = extcursor_free_block};

struct ext4_ext_path {
	struct buffer_head *p_bcb;
	struct ext4_extent_header *p_hdr;
	ssize_t p_ptr;
};

struct ext4_ext_cursor {
	struct ext4_extent_header *c_root;
	void *c_fsinfo;
	struct super_block *c_superblock;
	struct ext4_cursor_op c_cursor_op;
	struct ext4_ext_path *c_paths;
	size_t c_blocksz;
	int c_maxdepth;
};

static void
extcursor_root_dirty(struct ext4_ext_cursor *cur)
{
	ext4_mark_inode_dirty((struct inode *)cur->c_fsinfo);
}

static int
extcursor_alloc_block(struct ext4_ext_cursor *cur, ext4_fsblk_t *nblockp)
{
	int ret;
	ext4_lblk_t count = 1;
	*nblockp = ext4_new_meta_blocks((struct inode *)cur->c_fsinfo, 0, 0,
					&count, &ret);
	return ret;
}

static int
extcursor_free_block(struct ext4_ext_cursor *cur, ext4_fsblk_t block)
{
	ext4_ext_free_blocks((struct inode *)cur->c_fsinfo, block, 1, 0);
	return 0;
}

/*
 * ext4_ext_in_range -	Check whether @b provided is within the range
 * 			of an extent
 * @lblock:	Logical Block number
 * @first:	Starting logical block of an extent
 * @len:	Length of an extent
 *
 * Return true if @first <= @lblock < @first + @len
 */
#define ext4_ext_in_range(lblock, first, len)                                       \
	((lblock) >= (first) && (lblock) <= (first) + (len)-1)

/*
 * ext4_ext_header_depth -	Return the level of a node
 */
static inline int
ext4_ext_header_depth(struct ext4_extent_header *hdr)
{
	return (int)ext4_le16_to_cpu(hdr->eh_depth);
}

/*
 * ext4_ext_header_max_entries -	Return the maximum number a node can
 * 					contain
 */
static inline uint16_t
ext4_ext_header_max_entries(struct ext4_extent_header *hdr)
{
	return ext4_le16_to_cpu(hdr->eh_max);
}

/*
 * ext4_ext_header_entries -	Return the number of items a node contains
 */
static inline uint16_t
ext4_ext_header_entries(struct ext4_extent_header *hdr)
{
	return ext4_le16_to_cpu(hdr->eh_entries);
}

/*
 * ext4_ext_header_generation -	Return the generation number of a node
 */
static inline uint32_t
ext4_ext_header_generation(struct ext4_extent_header *hdr)
{
	return ext4_le16_to_cpu(hdr->eh_generation);
}

/*
 * ext4_ext_header_set_magic -	Initialize a node's header with magic number
 */
static inline void
ext4_ext_header_set_magic(struct ext4_extent_header *hdr)
{
	hdr->eh_magic = ext4_cpu_to_le16(EXT4_EXT_MAGIC);
}

/*
 * ext4_ext_header_set_depth -	Set the level of a node
 */
static inline void
ext4_ext_header_set_depth(struct ext4_extent_header *hdr, int depth)
{
	hdr->eh_depth = ext4_cpu_to_le16(depth);
}

/*
 * ext4_ext_header_set_max_entries -	Set the maximum numbers of items a node
 * can contain
 */
static inline void
ext4_ext_header_set_max_entries(struct ext4_extent_header *hdr, uint16_t max)
{
	hdr->eh_max = ext4_cpu_to_le16(max);
}

/*
 * ext4_ext_header_set_entries -	Set the numbers of items a node contains
 */
static inline void
ext4_ext_header_set_entries(struct ext4_extent_header *hdr, uint16_t entries)
{
	hdr->eh_entries = ext4_cpu_to_le16(entries);
}

/*
 * ext4_ext_header_set_generation -	Set the generation number of a node
 */
static inline void
ext4_ext_header_set_generation(struct ext4_extent_header *hdr,
			       uint32_t generation)
{
	hdr->eh_generation = ext4_cpu_to_le16(generation);
}

/*
 * ext4_ext_mark_unwritten -	Mark an extent unwritten
 */
static inline void
ext4_ext_mark_unwritten(struct ext4_extent *ext)
{
	/* We can not have an unwritten extent of zero length! */
	ext4_assert(
	    !((ext4_le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0));
	ext->ee_len |= ext4_cpu_to_le16(EXT_INIT_MAX_LEN);
}

/*
 * ext4_ext_is_unwritten -	Test if an extent is marked unwritten
 */
static inline int
ext4_ext_is_unwritten(struct ext4_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (ext4_le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

/*
 * ext4_ext_len -	Return the number of blocks covered by an extent
 */
static inline ext4_extlen_t
ext4_ext_len(struct ext4_extent *ext)
{
	return (ext4_le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN
		    ? ext4_le16_to_cpu(ext->ee_len)
		    : (ext4_le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

/*
 * ext4_ext_mark_initialized -	Remove an extent's unwritten marking
 */
static inline void
ext4_ext_mark_initialized(struct ext4_extent *ext)
{
	ext->ee_len = ext4_cpu_to_le16(ext4_ext_len(ext));
}

/*
 * ext4_ext_len -	Set the number of blocks covered by an extent
 */
static inline void
ext4_ext_store_len(struct ext4_extent *ext, ext4_extlen_t len)
{
	ext->ee_len = ext4_cpu_to_le16(len);
}

/*
 * ext4_ext_block -	combine low and high parts of physical block number into
 * 			ext4_fsblk_t
 */
static inline ext4_fsblk_t
ext4_ext_block(struct ext4_extent *ext)
{
	ext4_fsblk_t block;

	block = ext4_le32_to_cpu(ext->ee_start_lo);
	block |= ((ext4_fsblk_t)ext4_le16_to_cpu(ext->ee_start_hi) << 31) << 1;
	return block;
}

/*
 * ext4_idx_block -	combine low and high parts of a leaf physical block
 * 			number into ext4_fsblk_t
 */
static inline ext4_fsblk_t
ext4_idx_block(struct ext4_extent_idx *idx)
{
	ext4_fsblk_t block;

	block = ext4_le32_to_cpu(idx->ei_leaf_lo);
	block |= ((ext4_fsblk_t)ext4_le16_to_cpu(idx->ei_leaf_hi) << 31) << 1;
	return block;
}

/*
 * ext4_ext_lblock -	combine low and high parts of physical block number
 * 			into ext4_fsblk_t
 */
static inline ext4_lblk_t
ext4_ext_lblock(struct ext4_extent *ext)
{
	return ext4_le32_to_cpu(ext->ee_block);
}

/*
 * ext4_idx_lblock -	combine low and high parts of a leaf physical block
 * 			number into ext4_fsblk_t
 */
static inline ext4_lblk_t
ext4_idx_lblock(struct ext4_extent_idx *idx)
{
	return ext4_le32_to_cpu(idx->ei_block);
}

/*
 * ext4_ext_store_block -	stores a large physical block number into an
 * 				extent struct, breaking it into parts
 */
static inline void
ext4_ext_store_block(struct ext4_extent *ext, ext4_fsblk_t block)
{
	ext->ee_start_lo =
	    ext4_cpu_to_le32((unsigned long)(block & 0xffffffff));
	ext->ee_start_hi =
	    ext4_cpu_to_le16((unsigned long)((block >> 31) >> 1) & 0xffff);
}

/*
 * ext4_idx_store_block -	stores a large physical block number into an
 * index
 * 				struct, breaking it into parts
 */
static inline void
ext4_idx_store_block(struct ext4_extent_idx *idx, ext4_fsblk_t block)
{
	idx->ei_leaf_lo = ext4_cpu_to_le32((unsigned long)(block & 0xffffffff));
	idx->ei_leaf_hi =
	    ext4_cpu_to_le16((unsigned long)((block >> 31) >> 1) & 0xffff);
}

/*
 * ext4_ext_store_lblock -	stores a large physical block number into an
 * 				extent struct, breaking it into parts
 */
static inline void
ext4_ext_store_lblock(struct ext4_extent *ext, ext4_lblk_t lblock)
{
	ext->ee_block = ext4_cpu_to_le32(lblock);
}

/*
 * ext4_idx_store_lblock -	stores a large physical block number into an
 * 				index struct, breaking it into parts
 */
static inline void
ext4_idx_store_lblock(struct ext4_extent_idx *idx, ext4_lblk_t lblock)
{
	idx->ei_block = ext4_cpu_to_le32(lblock);
}

/*
 * ext4_ext_root_maxitems -	Calculate the maximum number of items root can
 * 				contains
 */
uint16_t
ext4_ext_root_maxitems()
{
	uint16_t room;

	room = EXT4_EXT_ROOT_SIZE - sizeof(struct ext4_extent_header);

#ifdef AGGRESSIVE_TEST
	return 3;
#else  /* AGGRESSIVE_TEST */
	return room / EXT4_EXT_ITEM_SIZE;
#endif /* AGGRESSIVE_TEST */
}

/*
 * ext4_ext_node_maxitems -	Calculate the maximum number of items a node can
 * 				contains
 * @blocksz:	block size
 */
uint16_t
ext4_ext_node_maxitems(size_t blocksz)
{
	uint16_t room;

	room = blocksz - sizeof(struct ext4_extent_header) -
	       sizeof(struct ext4_extent_tail);

#ifdef AGGRESSIVE_TEST
	return 4;
#else  /* AGGRESSIVE_TEST */
	return room / EXT4_EXT_ITEM_SIZE;
#endif /* AGGRESSIVE_TEST */
}

/*
 * ext4_ext_cursor_depth -	Return which depth of the root is at
 */
static inline int
ext4_ext_cursor_depth(struct ext4_ext_cursor *cur)
{
	return ext4_ext_header_depth(cur->c_root);
}

/*
 * ext4_ext_cursor_alloc -	Allocate a cursor for an extent tree
 *
 * @sb:		Filesystem's superblock
 * @root:	Address of tree's root
 * @fsinfo:	User data
 * @blocksz:	Filesystem block size
 */
struct ext4_ext_cursor *
ext4_ext_cursor_alloc(struct super_block *sb, void *root, void *fsinfo,
		      size_t blocksz)
{
	struct ext4_ext_path *paths;
	struct ext4_extent_header *hdr;
	int i;
	int rootdepth;
	struct ext4_ext_cursor *cur;

	hdr = root;
	rootdepth = ext4_ext_header_depth(hdr);

	cur = (struct ext4_ext_cursor *)ext4_malloc(
	    sizeof(struct ext4_ext_cursor));
	if (!cur)
		return NULL;

	paths = (struct ext4_ext_path *)ext4_zalloc(
	    sizeof(struct ext4_ext_path) * (rootdepth + 1));
	if (!paths) {
		ext4_free(cur);
		return NULL;
	}
	for (i = 0; i <= rootdepth; i++)
		paths[i].p_ptr = -1;
	cur->c_superblock = sb;
	cur->c_root = root;
	cur->c_fsinfo = fsinfo;
	cur->c_cursor_op = ext4_test_cursor_op;
	cur->c_paths = paths;
	cur->c_maxdepth = rootdepth;
	cur->c_blocksz = blocksz;

	cur->c_paths[rootdepth].p_bcb = NULL;
	cur->c_paths[rootdepth].p_hdr = cur->c_root;
	cur->c_paths[rootdepth].p_ptr = -1;
	return cur;
}

/*
 * ext4_ext_path_unpin - Unpin the buffer referenced
 */
static void
ext4_ext_path_unpin(struct ext4_ext_path *pathp)
{
	if (pathp->p_hdr) {
		if (pathp->p_bcb) {
			fs_brelse(pathp->p_bcb);
			pathp->p_bcb = NULL;
		}
		pathp->p_hdr = NULL;
		pathp->p_ptr = 0;
	}
}

/*
 * ext4_ext_cursor_unpin -	Unpin all the buffers referenced
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of buffer to be unpinned.
 * 		If @depth is negative all buffers will be
 * 		unpinned
 * @nrlevel:	The number of levels to be unpinned
 */
void
ext4_ext_cursor_unpin(struct ext4_ext_cursor *cur, int depth, int nrlevel)
{
	int i;
	int maxdepth;

	maxdepth = cur->c_maxdepth;

	if (depth < 0) {
		for (i = 0; i <= maxdepth; i++)
			ext4_ext_path_unpin(cur->c_paths + i);

	} else {
		for (i = depth; i <= maxdepth && i < depth + nrlevel; i++)
			ext4_ext_path_unpin(cur->c_paths + i);
	}
}

/*
 * ext4_ext_cursor_reset_rootpath -	Resize the paths array in the cursor and
 * 					reset the root level of the paths array.
 * 					This routine will always succeed if path
 * 					array size is being shrunk or remains
 * 					the same.
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 on success, or ENOMEM when memory is insufficient.
 */
static int
ext4_ext_cursor_reset_rootpath(struct ext4_ext_cursor *cur)
{
	struct ext4_ext_path *paths;
	int rootdepth;

	rootdepth = ext4_ext_cursor_depth(cur);

	if (rootdepth > cur->c_maxdepth) {
		int nrlevel = cur->c_maxdepth;

		paths = (struct ext4_ext_path *)ext4_malloc(
		    sizeof(struct ext4_ext_path) * (rootdepth + 1));
		if (!paths)
			return ENOMEM;

		memcpy(paths, cur->c_paths,
		       nrlevel * sizeof(struct ext4_ext_path));
		ext4_free(cur->c_paths);
		cur->c_paths = paths;
		cur->c_maxdepth = rootdepth;
	}

	cur->c_paths[rootdepth].p_bcb = NULL;
	cur->c_paths[rootdepth].p_hdr = cur->c_root;
	cur->c_paths[rootdepth].p_ptr = -1;
	return 0;
}

/*
 * ext4_ext_cursor_set_buf -	Set the path array at a level in a cursor
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of buffer fields to be set.
 * @ptr:	Item pointer
 */
void
ext4_ext_cursor_set_buf(struct ext4_ext_cursor *cur, int depth,
			struct ext4_ext_path *pathp)
{
	ext4_assert(!cur->c_paths[depth].p_hdr);
	cur->c_paths[depth] = *pathp;
}

/*
 * ext4_ext_cursor_free -	Free a cursor
 */
void
ext4_ext_cursor_free(struct ext4_ext_cursor *cur)
{
	ext4_ext_cursor_unpin(cur, -1, -1);
	ext4_free(cur->c_paths);
	ext4_free(cur);
}

/*
 * ext4_ext_lblock_cmp -	Compare two logical blocks
 *
 * @a:	The first logical block as operand
 * @b:	The second logical block as operand
 *
 * Return -1 if @a < @b, 1 if @a > @b. If they are equal
 * then return 0.
 */
static inline int
ext4_ext_lblock_cmp(ext4_lblk_t a, ext4_lblk_t b)
{
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

/*
 * ext4_ext_binsearch_node -	Do binary search in a node whose depth is
 * 				greater than 0, and find an item whose
 * 				logical block is smaller or equal to
 * 				@lblock
 *
 * @buf:	Buffer address
 * @lblock:	Logical block to be looked up in the node
 * @ptr:	Item pointer returned
 *
 * If @lblock is smaller than the logical block of the first item in the node,
 * @ptr will be set to 0.
 */
static void
ext4_ext_binsearch_node(void *buf, ext4_lblk_t lblock, ssize_t *ptr)
{
	int diff = 0;
	/* search range: @lower <= @mid <= @upper */
	ssize_t lower;
	ssize_t upper;
	ssize_t mid = 0;
	struct ext4_extent_header *hdr;
	struct ext4_extent_idx *idx;

	hdr = buf;
	lower = 0;
	upper = ext4_ext_header_entries(hdr) - 1;

	while (lower <= upper) {
		mid = (lower + upper) / 2;
		idx = EXT_FIRST_INDEX(hdr) + mid;
		diff = ext4_ext_lblock_cmp(lblock, ext4_idx_lblock(idx));
		if (!diff)
			break;
		else if (diff < 0)
			upper = mid - 1;
		else
			lower = mid + 1;
	}
	/*
	 * Decrement @mid if @lblock is smaller than the logical block of the
	 * index.
	 */
	if (diff < 0 && mid)
		--mid;
	*ptr = mid;
}

/*
 * ext4_ext_binsearch_leaf -	Do binary search in a leaf, whose logical block
 * 				is smaller or equal to @lblock
 *
 * @buf:	Buffer address
 * @lblock:	Logical block to be looked up in the node
 * @ptr:	Item pointer returned
 *
 * If @lblock is smaller than the logical block of the first item in the node,
 * @ptr will be set to 0.
 */
static void
ext4_ext_binsearch_leaf(void *buf, ext4_lblk_t lblock, ssize_t *ptr)
{
	int diff = 0;
	/* search range: @lower <= @mid <= @upper */
	ssize_t lower;
	ssize_t upper;
	ssize_t mid = 0;
	struct ext4_extent_header *hdr;
	struct ext4_extent *ext;

	hdr = buf;
	lower = 0;
	upper = ext4_ext_header_entries(hdr) - 1;

	while (lower <= upper) {
		mid = (lower + upper) / 2;
		ext = EXT_FIRST_EXTENT(hdr) + mid;
		diff = ext4_ext_lblock_cmp(lblock, ext4_ext_lblock(ext));
		if (ext4_ext_in_range(lblock, ext4_ext_lblock(ext),
				      ext4_ext_len(ext))) {
			diff = 0;
			break;
		} else if (diff < 0) {
			upper = mid - 1;
		} else {
			lower = mid + 1;
		}
	}
	/*
	 * Decrement @mid if @lblock is smaller than the logical block of the
	 * extent.
	 */
	if (diff < 0 && mid)
		--mid;
	*ptr = mid;
}

/*
 * ext4_ext_lookup_extent -	Look up the extent which covers @lblock
 *
 * @cur:	Cursor to an extent tree
 * @lblock:	Logical block
 * @notfound:	Return result of the search
 *
 * Even if there is no matching extent, item pointers in the cursor is still
 * set so that caller in future can insert an extent in the right place
 *
 * Return 0 on success, EIO on currupted block, or return values of fs_bread().
 */
int
ext4_ext_lookup_extent(struct ext4_ext_cursor *cur, ext4_lblk_t lblock,
		       bool *notfound)
{
	int ret = 0;
	int depth;
	int rootdepth;
	struct super_block *sb;

	sb = cur->c_superblock;
	rootdepth = ext4_ext_cursor_depth(cur);

	if (notfound)
		*notfound = true;

	ext4_assert(cur->c_paths[rootdepth].p_hdr);

	for (depth = rootdepth; depth >= 0; depth--) {
		struct ext4_ext_path npath;
		struct ext4_extent_header *hdr;

		hdr = cur->c_paths[depth].p_hdr;
		if (depth)
			ext4_ext_binsearch_node(hdr, lblock,
						&cur->c_paths[depth].p_ptr);
		else
			ext4_ext_binsearch_leaf(hdr, lblock,
						&cur->c_paths[depth].p_ptr);
		if (depth) {
			struct ext4_extent_idx *idx;
			void *data;

			idx = EXT_FIRST_INDEX(hdr) + cur->c_paths[depth].p_ptr;
			npath.p_bcb = fs_bread(sb, ext4_idx_block(idx), &ret);
			if (ret)
				break;
			data = npath.p_bcb->b_data;
			npath.p_hdr = (struct ext4_extent_header *)data;
			ext4_ext_cursor_set_buf(cur, depth - 1, &npath);

			hdr = npath.p_hdr;
			if (hdr->eh_magic != EXT4_EXT_MAGIC) {
				ret = EIO;
				break;
			}
		} else {
			struct ext4_extent *ext =
			    EXT_FIRST_EXTENT(hdr) + cur->c_paths[0].p_ptr;
			uint16_t nritems = ext4_ext_header_entries(hdr);

			if (nritems &&
			    ext4_ext_in_range(lblock, ext4_ext_lblock(ext),
					      ext4_ext_len(ext))) {
				if (notfound)
					*notfound = false;
			}
		}
	}
	if (ret)
		ext4_ext_cursor_unpin(cur, -1, -1);
	return ret;
}

/*
 * ext4_ext_cursor_ext -	Return the extent pointed by
 * 				a given cursor. If the cursor
 * 				doesn't point to anything, NULL
 * 				is returned
 */
struct ext4_extent *
ext4_ext_cursor_ext(struct ext4_ext_cursor *cur)
{
	struct ext4_extent_header *hdr;

	hdr = cur->c_paths[0].p_hdr;

	if (!hdr || cur->c_paths[0].p_ptr == -1)
		return NULL;
	return EXT_FIRST_EXTENT(hdr) + cur->c_paths[0].p_ptr;
}

/*
 * ext4_ext_tree_empty -	Return whether the tree is empty
 */
bool
ext4_ext_tree_empty(struct ext4_ext_cursor *cur)
{
	struct ext4_extent_header *hdr = cur->c_root;
	return !ext4_ext_header_entries(hdr);
}

/*
 * ext4_ext_node_lblock -	Return the logical block index of a node
 */
static inline ext4_lblk_t
ext4_ext_node_lblock(struct ext4_extent_header *hdr)
{
	union ext4_extent_item *itemp = EXT_FIRST_ITEM(hdr);
	return ext4_ext_header_depth(hdr) ? ext4_idx_lblock(&itemp->i)
					  : ext4_ext_lblock(&itemp->e);
}

/*
 * ext4_ext_split_node -	Split a node in two, each contains about half of
 * 				the number of entries of the original node
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of the node to be split
 * @nblocknr:	A new block provided by caller
 * @pathp:	Path to store buffer and pointer if path replacement will take
 * 		place in @cur
 *
 * Return 0 on success, or return values of fs_bwrite().
 */
static int
ext4_ext_split_node(struct ext4_ext_cursor *cur, int depth, ext4_fsblk_t nblocknr,
		    struct ext4_ext_path *pathp)
{
	int ret;
	ssize_t ptr;
	ssize_t nptr = -1;
	struct buffer_head *nbcb;
	uint16_t nritems;
	uint16_t nnritems;
	struct super_block *sb;
	struct ext4_extent_header *hdr;
	struct ext4_extent_header *nhdr;
	union ext4_extent_item *items;
	union ext4_extent_item *nitems;

	ext4_assert(depth != ext4_ext_cursor_depth(cur));

	ptr = cur->c_paths[depth].p_ptr;
	sb = cur->c_superblock;

	nbcb = fs_bwrite(sb, nblocknr, &ret);
	if (ret)
		return ret;

	hdr = cur->c_paths[depth].p_hdr;
	nhdr = (struct ext4_extent_header *)nbcb->b_data;

	items = EXT_FIRST_ITEM(hdr);
	nitems = EXT_FIRST_ITEM(nhdr);
	nritems = ext4_ext_header_entries(hdr) / 2;
	nnritems = ext4_ext_header_entries(hdr) - nritems;

	ext4_ext_header_set_magic(nhdr);
	ext4_ext_header_set_depth(nhdr, depth);
	ext4_ext_header_set_max_entries(nhdr,
					ext4_ext_node_maxitems(cur->c_blocksz));
	ext4_ext_header_set_generation(nhdr, 0);

	ext4_ext_header_set_entries(hdr, nritems);
	ext4_ext_header_set_entries(nhdr, nnritems);

	memcpy(nitems, items + nritems, nnritems * EXT4_EXT_ITEM_SIZE);
	memset(items + nritems, 0, nnritems * EXT4_EXT_ITEM_SIZE);

	fs_mark_buffer_dirty(cur->c_paths[depth].p_bcb);
	fs_mark_buffer_dirty(nbcb);

	if (ptr >= nritems)
		nptr = ptr - nritems;

	pathp->p_bcb = nbcb;
	pathp->p_hdr = nhdr;
	pathp->p_ptr = nptr;
	return 0;
}

/*
 * ext4_ext_tree_grow -	Grow the extent tree
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of the tree root
 * @nblocknr:	A new block provided by caller
 * @pathp:	Path to store buffer and pointer
 *
 * Return 0 on success, or return values of fs_bwrite().
 */
static int
ext4_ext_tree_grow(struct ext4_ext_cursor *cur, int depth, ext4_fsblk_t nblocknr,
		   struct ext4_ext_path *pathp)
{
	int ret;
	struct buffer_head *nbcb;
	uint16_t nritems;
	uint16_t nnritems;
	struct super_block *sb;
	struct ext4_extent_header *hdr;
	struct ext4_extent_header *nhdr;
	union ext4_extent_item *items;
	union ext4_extent_item *nitems;
	ssize_t nptr;

	sb = cur->c_superblock;

	nbcb = fs_bwrite(sb, nblocknr, &ret);
	if (ret)
		return ret;

	hdr = cur->c_root;
	nhdr = (struct ext4_extent_header *)nbcb->b_data;

	items = EXT_FIRST_ITEM(hdr);
	nitems = EXT_FIRST_ITEM(nhdr);

	nnritems = nritems = ext4_ext_header_entries(hdr);

	ext4_ext_header_set_magic(nhdr);
	ext4_ext_header_set_depth(nhdr, depth);
	ext4_ext_header_set_max_entries(nhdr,
					ext4_ext_node_maxitems(cur->c_blocksz));
	ext4_ext_header_set_generation(nhdr, 0);
	ext4_ext_header_set_entries(nhdr, nnritems);

	memcpy(nitems, items, nnritems * EXT4_EXT_ITEM_SIZE);

	ext4_ext_header_set_depth(hdr, depth + 1);
	ext4_ext_header_set_entries(hdr, 0);
	memset(items, 0, nritems * EXT4_EXT_ITEM_SIZE);

	cur->c_cursor_op.c_root_dirty_func(cur);
	fs_mark_buffer_dirty(nbcb);

	nptr = cur->c_paths[depth].p_ptr;

	pathp->p_bcb = nbcb;
	pathp->p_hdr = nhdr;
	pathp->p_ptr = nptr;
	return 0;
}

/*
 * ext4_ext_update_index -	Update the index of nodes starting from @depth
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level to start updating the indice at
 * @force:	Force to update along all the levels to the root
 */
static void
ext4_ext_update_index(struct ext4_ext_cursor *cur, int depth, int force)
{
	int i;
	int rootdepth;

	rootdepth = ext4_ext_cursor_depth(cur);

	for (i = depth + 1; i <= rootdepth; i++) {
		struct ext4_extent_header *hdr =
		    (cur->c_paths[i].p_hdr);
		struct ext4_extent_header *childhdr =
		    cur->c_paths[i - 1].p_hdr;
		ssize_t ptr = cur->c_paths[i].p_ptr;

		if (cur->c_paths[i - 1].p_ptr)
			break;
		if (i > 1) {
			struct ext4_extent_idx *idx =
			    EXT_FIRST_INDEX(hdr) + ptr;
			struct ext4_extent_idx *childidx =
			    EXT_FIRST_INDEX(childhdr);

			if (ext4_idx_lblock(idx) != ext4_idx_lblock(childidx)) {
				ext4_idx_store_lblock(
				    idx, ext4_idx_lblock(childidx));
				if (i < rootdepth)
					fs_mark_buffer_dirty(
					    cur->c_paths[i].p_bcb);
				else
					cur->c_cursor_op.c_root_dirty_func(cur);
			} else if (!force)
				break;
		} else {
			struct ext4_extent_idx *idx =
			    EXT_FIRST_INDEX(hdr) + ptr;
			struct ext4_extent *childext =
			    EXT_FIRST_EXTENT(childhdr);

			if (ext4_idx_lblock(idx) != ext4_ext_lblock(childext)) {
				ext4_idx_store_lblock(
				    idx, ext4_ext_lblock(childext));
				if (i < rootdepth)
					fs_mark_buffer_dirty(
					    cur->c_paths[i].p_bcb);
				else
					cur->c_cursor_op.c_root_dirty_func(cur);
			} else if (!force)
				break;
		}
	}
}

/*
 * ext4_ext_insert_item -	Insert an item into the node at @depth
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of the node to be operated on
 * @nitems:	The item to be inserted
 * @updptr:	Update the item pointer in the node at @depth
 */
static void
ext4_ext_insert_item(struct ext4_ext_cursor *cur, int depth,
		     union ext4_extent_item *nitems, bool updptr)
{
	struct ext4_extent_header *hdr;
	uint16_t nritems;
	ssize_t ptr;
	union ext4_extent_item *item;

	hdr = cur->c_paths[depth].p_hdr;
	nritems = ext4_ext_header_entries(hdr);
	ptr = (nritems) ? cur->c_paths[depth].p_ptr : 0;
	item = EXT_FIRST_ITEM(hdr) + ptr;

	ext4_assert(EXT_HAS_FREE_INDEX(hdr));

	if (nritems) {
		ssize_t shiftnritems;

		if (depth) {
			if (ext4_idx_lblock(&item->i) <
			    ext4_idx_lblock(&nitems->i)) {
				ptr++;
				item++;
			}
		} else {
			if (ext4_ext_lblock(&item->e) + ext4_ext_len(&item->e) -
				1 <
			    ext4_ext_lblock(&nitems->e)) {
				ptr++;
				item++;
			}
		}
		shiftnritems = EXT_LAST_ITEM(hdr) - item + 1;
		if (shiftnritems)
			memmove(item + 1, item,
				shiftnritems * EXT4_EXT_ITEM_SIZE);
		memcpy(item, nitems, EXT4_EXT_ITEM_SIZE);
	} else {
		memcpy(item, nitems, EXT4_EXT_ITEM_SIZE);
	}
	if (updptr)
		cur->c_paths[depth].p_ptr = ptr;
	ext4_ext_header_set_entries(hdr, ext4_ext_header_entries(hdr) + 1);
	if (depth == ext4_ext_cursor_depth(cur))
		cur->c_cursor_op.c_root_dirty_func(cur);
	else
		fs_mark_buffer_dirty(cur->c_paths[depth].p_bcb);
}

/*
 * ext4_ext_nrlevel_need_split -	Return the number of levels to be split
 *
 * @cur:	Cursor to an extent tree
 */
static int
ext4_ext_nrlevel_need_split(struct ext4_ext_cursor *cur)
{
	int i;
	int rootdepth;

	rootdepth = ext4_ext_cursor_depth(cur);

	for (i = 0; i <= rootdepth; i++) {
		struct ext4_extent_header *hdr =
		    cur->c_paths[i].p_hdr;

		if (EXT_HAS_FREE_INDEX(hdr))
			break;
	}
	return i;
}

/*
 * ext4_ext_ensure_unfull -	Ensure the leaf is unfull by splitting and
 * 				growing of extent tree
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 on success, ENOMEM when memory is insufficient, or return values of
 * ext4_cursor_op::c_alloc_block_func(), ext4_ext_split_node() or
 * ext4_ext_tree_grow().
 */
static int
ext4_ext_ensure_unfull(struct ext4_ext_cursor *cur)
{
	int ret = 0;
	ext4_fsblk_t *nblocknrs = NULL;
	int rootdepth;
	int nrlevel;
	int nrallocs = 0;

	rootdepth = ext4_ext_cursor_depth(cur);
	nrlevel = ext4_ext_nrlevel_need_split(cur);

	if (nrlevel) {
		uint16_t i;
		ssize_t pptr;
		ext4_lblk_t prlblock;
		union ext4_extent_item nitems;

		nblocknrs =
		    (ext4_fsblk_t *)ext4_malloc(nrlevel * sizeof(ext4_fsblk_t));
		if (!nblocknrs) {
			ret = ENOMEM;
			goto out;
		}
		for (i = 0; i < nrlevel; i++, nrallocs++) {
			ret = cur->c_cursor_op.c_alloc_block_func(cur,
								  nblocknrs + i);
			if (ret)
				goto out;
		}
		for (i = 0; i < nrlevel; i++) {
			ssize_t ptr;
			ext4_lblk_t rlblock;
			struct ext4_ext_path path;

			if (i < rootdepth) {
				ret = ext4_ext_split_node(cur, i, nblocknrs[i],
							  &path);
				if (ret)
					goto out;
			} else {
				ret = ext4_ext_tree_grow(cur, i, nblocknrs[i],
							 &path);
				if (ret)
					goto out;
				rootdepth++;
				ret = ext4_ext_cursor_reset_rootpath(cur);
				if (ret)
					goto out;
				cur->c_paths[rootdepth].p_ptr = 0;
			}
			ptr = path.p_ptr;
			rlblock = ext4_ext_node_lblock(path.p_hdr);
			if (path.p_ptr != -1) {
				ext4_ext_cursor_unpin(cur, i, 1);
				ext4_ext_cursor_set_buf(cur, i, &path);
			} else {
				ext4_ext_path_unpin(&path);
			}
			if (i) {
				memset(&nitems, 0, EXT4_EXT_ITEM_SIZE);
				ext4_idx_store_lblock(&nitems.i, prlblock);
				ext4_idx_store_block(&nitems.i, nblocknrs[i - 1]);
				ext4_ext_insert_item(cur, i, &nitems,
						     pptr != -1);
			}
			pptr = ptr;
			prlblock = rlblock;
		}
		memset(&nitems, 0, EXT4_EXT_ITEM_SIZE);
		ext4_idx_store_lblock(&nitems.i, prlblock);
		ext4_idx_store_block(&nitems.i, nblocknrs[i - 1]);
		ext4_ext_insert_item(cur, i, &nitems, pptr != -1);
	}

out:
	if (nblocknrs) {
		if (ret) {
			uint16_t i = nrallocs;

			while (i--)
				cur->c_cursor_op.c_free_block_func(cur,
								   nblocknrs[i]);
		}
		ext4_free(nblocknrs);
	}

	return ret;
}

/*
 * ext4_ext_insert -	Insert a new extent into an extent tree
 *
 * @cur:	Cursor to an extent tree
 * @next:	New extent to insert
 *
 * Return 0 on success, or return values of ext4_ext_ensure_unfull().
 */
int
ext4_ext_insert(struct ext4_ext_cursor *cur, struct ext4_extent *next)
{
	int ret;

	ret = ext4_ext_ensure_unfull(cur);
	if (ret)
		return ret;

	ext4_ext_insert_item(cur, 0, (union ext4_extent_item *)next, true);
	ext4_ext_update_index(cur, 0, 0);
	return 0;
}

/*
 * ext4_ext_delete_item -	Delete an item from the node at @depth pointed
 * to
 * 				by item pointer in the node at given level
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of the node to be operated on
 */
static void
ext4_ext_delete_item(struct ext4_ext_cursor *cur, int depth)
{
	ssize_t ptr;
	ssize_t nritems;
	struct ext4_extent_header *hdr;
	union ext4_extent_item *item;

	ptr = cur->c_paths[depth].p_ptr;
	hdr = cur->c_paths[depth].p_hdr;
	item = EXT_FIRST_ITEM(hdr) + ptr;

	ext4_assert(ext4_ext_header_entries(hdr));

	nritems = EXT_LAST_ITEM(hdr) - (item + 1) + 1;
	if (nritems) {
		memmove(item, item + 1, nritems * EXT4_EXT_ITEM_SIZE);
		memset(EXT_LAST_ITEM(hdr), 0, EXT4_EXT_ITEM_SIZE);
	} else {
		memset(item, 0, EXT4_EXT_ITEM_SIZE);
	}
	ext4_ext_header_set_entries(hdr, ext4_ext_header_entries(hdr) - 1);
	if (depth == ext4_ext_cursor_depth(cur))
		cur->c_cursor_op.c_root_dirty_func(cur);
	else
		fs_mark_buffer_dirty(cur->c_paths[depth].p_bcb);
}

/*
 * ext4_ext_may_merge -	Return whether node-merging may take place
 * 			or not in a node
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of buffer to be checked.
 *
 * Return true if node-merging may take place.
 */
static bool
ext4_ext_may_merge(struct ext4_ext_cursor *cur, int depth)
{
	struct ext4_extent_header *hdr;
	uint16_t nritems;

	hdr = cur->c_paths[depth].p_hdr;
	nritems = ext4_ext_header_entries(hdr);

	return nritems < ext4_ext_header_max_entries(hdr) / 2;
}

/*
 * ext4_ext_left_sibling -	Return cursor to left sibling of node at given
 * 				level
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of buffer to be checked
 * @ncurp:	A place to store the address of new cursor at.
 * @nosibp:	A place to return whether there is sibling
 *
 * Return 0 if there is no error, ENOMEM if there is not enough memory space,
 * or return values of ext4_ext_lookup_extent().
 */
static int
ext4_ext_left_sibling(struct ext4_ext_cursor *cur, int depth,
		      struct ext4_ext_cursor **ncurp, bool *nosibp)
{
	int ret = 0;
	ext4_lblk_t lblock;
	bool nosib = true;
	struct ext4_ext_cursor *ncur = NULL;
	struct ext4_extent_header *hdr;
	union ext4_extent_item *itemp;

	hdr = cur->c_paths[depth].p_hdr;
	itemp = EXT_FIRST_ITEM(hdr);

	ext4_assert(ncurp);

	if (!depth)
		lblock = ext4_ext_lblock(&itemp->e);
	else
		lblock = ext4_idx_lblock(&itemp->i);
	if (lblock)
		lblock--;

	ncur = ext4_ext_cursor_alloc(cur->c_superblock, cur->c_root,
				     cur->c_fsinfo, cur->c_blocksz);
	if (!ncur) {
		ret = ENOMEM;
		goto out;
	}

	ret = ext4_ext_lookup_extent(ncur, lblock, NULL);
	if (ret)
		goto out;

	if (ext4_buf_blocknr(ncur->c_paths[depth].p_bcb) ==
	    ext4_buf_blocknr(cur->c_paths[depth].p_bcb))
		goto out;

	nosib = false;
out:
	*nosibp = nosib;
	*ncurp = ncur;
	return ret;
}

/*
 * ext4_ext_right_sibling -	Return cursor to right sibling of node at given
 * 				level
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level of buffer to be checked
 * @ncurp:	A place to store the address of new cursor at
 * @nosibp:	A place to return whether there is sibling
 *
 * Return 0 if there is no error, ENOMEM if there is not enough memory space,
 * or return values of ext4_ext_lookup_extent().
 */
static int
ext4_ext_right_sibling(struct ext4_ext_cursor *cur, int depth,
		       struct ext4_ext_cursor **ncurp, bool *nosibp)
{
	int ret = 0;
	int i;
	ext4_lblk_t lblock;
	bool nosib = true;
	struct ext4_ext_cursor *ncur = NULL;
	int rootdepth;
	struct ext4_extent_header *hdr;
	union ext4_extent_item *itemp;

	rootdepth = ext4_ext_cursor_depth(cur);
	hdr = cur->c_paths[depth].p_hdr;
	itemp = EXT_FIRST_ITEM(hdr);

	ext4_assert(ncurp);

	if (!depth)
		lblock = ext4_ext_lblock(&itemp->e);
	else
		lblock = ext4_idx_lblock(&itemp->i);

	for (i = depth + 1; i <= rootdepth; i++) {
		ssize_t ptr = cur->c_paths[i].p_ptr;

		hdr = cur->c_paths[i].p_hdr;
		if (ptr++ < ext4_ext_header_entries(hdr) - 1) {
			struct ext4_extent_idx *idx =
			    EXT_FIRST_INDEX(hdr) + ptr;
			nosib = false;
			lblock = ext4_idx_lblock(idx);
			break;
		}
	}
	ncur = ext4_ext_cursor_alloc(cur->c_superblock, cur->c_root,
				     cur->c_fsinfo, cur->c_blocksz);
	if (!ncur) {
		ret = ENOMEM;
		goto out;
	}

	ret = ext4_ext_lookup_extent(ncur, lblock, NULL);
	if (ret)
		goto out;

out:
	*nosibp = nosib;
	*ncurp = ncur;
	return ret;
}

/*
 * ext4_ext_decrement -	Seek to the previous extent
 *
 * @cur:	Cursor to an extent tree
 * @noprevp:	A place to return whether the current extent
 * 		is the left-most extent already
 *
 * Return 0 on success, EIO on currupted block, or return values of fs_bread().
 */
int
ext4_ext_decrement(struct ext4_ext_cursor *cur, bool *noprevp)
{
	int ret = 0;
	int i;
	int depth;
	ssize_t ptr;
	bool noprev = true;
	int rootdepth;
	struct super_block *sb;

	rootdepth = ext4_ext_cursor_depth(cur);
	sb = cur->c_superblock;

	for (i = 0; i <= rootdepth; i++) {
		struct ext4_extent_header *hdr;
		
		hdr = cur->c_paths[i].p_hdr;
		ptr = cur->c_paths[i].p_ptr;
		if (hdr && ptr && ptr != -1)
			break;
	}
	depth = i;
	if (depth > rootdepth)
		goto out;

	cur->c_paths[depth].p_ptr--;
	for (i = depth - 1; i >= 0; i--) {
		int udepth = i + 1;
		struct ext4_ext_path npath;
		struct ext4_extent_header *hdr;
		struct ext4_extent_idx *idx;
		void *data;

		hdr = cur->c_paths[udepth].p_hdr;
		idx = EXT_FIRST_INDEX(hdr) + cur->c_paths[udepth].p_ptr;

		ext4_ext_cursor_unpin(cur, i, 1);
		npath.p_bcb = fs_bread(sb, ext4_idx_block(idx), &ret);
		if (ret)
			goto out;
		data = npath.p_bcb->b_data;
		npath.p_hdr = (struct ext4_extent_header *)data;
		npath.p_ptr = -1;
		ext4_ext_cursor_set_buf(cur, i, &npath);

		hdr = npath.p_hdr;
		if (hdr->eh_magic != EXT4_EXT_MAGIC) {
			ret = EIO;
			goto out;
		}

		cur->c_paths[i].p_ptr = ext4_ext_header_entries(hdr) - 1;
	}
	noprev = false;
out:
	if (noprevp)
		*noprevp = noprev;
	return ret;
}

/*
 * ext4_ext_increment -	Seek to the next extent
 *
 * @cur:	Cursor to an extent tree
 * @nonextp:	A place to return whether the current extent
 * 		is the right-most extent already
 *
 * Return 0 on success, EIO on currupted block, or return values of fs_bread().
 */
int
ext4_ext_increment(struct ext4_ext_cursor *cur, bool *nonextp)
{
	int ret = 0;
	int i;
	int depth;
	ssize_t ptr;
	bool nonext = true;
	int rootdepth;
	struct super_block *sb;

	rootdepth = ext4_ext_cursor_depth(cur);
	sb = cur->c_superblock;

	for (i = 0; i <= rootdepth; i++) {
		struct ext4_extent_header *hdr;

		hdr = cur->c_paths[i].p_hdr;
		ptr = cur->c_paths[i].p_ptr;
		if (hdr && ptr != -1 && ptr < ext4_ext_header_entries(hdr) - 1)
			break;
	}
	depth = i;
	if (depth > rootdepth)
		goto out;

	cur->c_paths[depth].p_ptr++;
	for (i = depth - 1; i >= 0; i--) {
		int udepth = i + 1;
		struct ext4_ext_path npath;
		struct ext4_extent_header *hdr;
		struct ext4_extent_idx *idx;
		void *data;
		
		hdr = cur->c_paths[udepth].p_hdr;
		idx = EXT_FIRST_INDEX(hdr) + cur->c_paths[udepth].p_ptr;

		ext4_ext_cursor_unpin(cur, i, 1);
		npath.p_bcb = fs_bread(sb, ext4_idx_block(idx), &ret);
		if (ret)
			goto out;
		data = npath.p_bcb->b_data;
		npath.p_hdr = (struct ext4_extent_header *)data;
		npath.p_ptr = 0;
		ext4_ext_cursor_set_buf(cur, i, &npath);

		hdr = npath.p_hdr;
		if (hdr->eh_magic != EXT4_EXT_MAGIC) {
			ret = EIO;
			goto out;
		}
	}
	nonext = false;
out:
	if (nonextp)
		*nonextp = nonext;
	return ret;
}

/*
 * ext4_ext_reload_paths -	Reload the paths in a cursor
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level to start the reload at
 *
 * Return 0 on success, EIO on currupted block, or return values of fs_bread().
 */
int
ext4_ext_reload_paths(struct ext4_ext_cursor *cur, int depth)
{
	int ret = 0;
	int i;
	struct ext4_extent_header *hdr;
	struct super_block *sb;

	sb = cur->c_superblock;
	hdr = cur->c_paths[depth].p_hdr;

	if (cur->c_paths[depth].p_ptr > ext4_ext_header_entries(hdr) - 1)
		cur->c_paths[depth].p_ptr = ext4_ext_header_entries(hdr) - 1;

	for (i = depth - 1; i >= 0; i--) {
		int udepth = i + 1;
		struct ext4_ext_path npath;
		struct ext4_extent_idx *idx;
		void *data;

		hdr = cur->c_paths[udepth].p_hdr;
		idx = EXT_FIRST_INDEX(hdr) + cur->c_paths[udepth].p_ptr;

		if (cur->c_paths[i].p_hdr &&
		    ext4_buf_blocknr(cur->c_paths[i].p_bcb) ==
			ext4_idx_block(idx)) {
			if (cur->c_paths[i].p_ptr == -1)
				cur->c_paths[i].p_ptr = 0;
			continue;
		}

		ext4_ext_cursor_unpin(cur, i, 1);
		npath.p_bcb = fs_bread(sb, ext4_idx_block(idx), &ret);
		if (ret)
			goto out;
		data = npath.p_bcb->b_data;
		npath.p_hdr = (struct ext4_extent_header *)data;
		npath.p_ptr = 0;
		ext4_ext_cursor_set_buf(cur, i, &npath);

		hdr = npath.p_hdr;
		if (hdr->eh_magic != EXT4_EXT_MAGIC) {
			ret = EIO;
			goto out;
		}
	}
out:
	return ret;
}

/*
 * ext4_ext_try_merge_left -	Merge the node at given level to its left
 * 				sibling
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level where merging takes place at
 * @ncurp:	A place to store the address of new cursor at if merging
 * 		succeeds
 * @mergedp:	A place to return whether merging succeeds. If merging to left
 * 		succeeds, *@mergedp will be set to 1
 *
 * Return 0 if there is no error, or return values of ext4_ext_left_sibling().
 */
static int
ext4_ext_try_merge_left(struct ext4_ext_cursor *cur, int depth,
			struct ext4_ext_cursor **ncurp, int *mergedp)
{
	int ret;
	bool nosib;
	int merged = 0;
	uint16_t nritems;
	uint16_t snritems;
	struct ext4_ext_cursor *ncur = NULL;
	struct ext4_extent_header *hdr;
	struct ext4_extent_header *shdr;

	*ncurp = NULL;
	*mergedp = 0;

	ret = ext4_ext_left_sibling(cur, depth, &ncur, &nosib);
	if (ret || nosib)
		goto out;

	hdr = cur->c_paths[depth].p_hdr;
	shdr = ncur->c_paths[depth].p_hdr;
	nritems = ext4_ext_header_entries(hdr);
	snritems = ext4_ext_header_entries(shdr);
	if (ext4_ext_may_merge(cur, depth) &&
	    nritems + snritems <= ext4_ext_header_max_entries(shdr)) {
		union ext4_extent_item *itemp = EXT_LAST_ITEM(shdr) + 1;

		memcpy(itemp, EXT_FIRST_ITEM(hdr),
		       nritems * EXT4_EXT_ITEM_SIZE);
		ext4_ext_header_set_entries(shdr, snritems + nritems);
		fs_mark_buffer_dirty(ncur->c_paths[depth].p_bcb);
		merged = 1;
	}
out:
	if (!merged && ncur) {
		ext4_ext_cursor_free(ncur);
		ncur = NULL;
	}
	*mergedp = merged;
	*ncurp = ncur;
	return ret;
}

/*
 * ext4_ext_try_merge_right -	Merge the node at given level to its right
 * 				sibling
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level where merging takes place at
 * @ncurp:	A place to store the address of new cursor at if merging
 * 		succeeds
 * @mergedp:	A place to return whether merging succeeds. If merging to right
 * 		succeeds, *@mergedp will be set to 2
 *
 * Return 0 if there is no error, or return values of ext4_ext_right_sibling().
 */
static int
ext4_ext_try_merge_right(struct ext4_ext_cursor *cur, int depth,
			 struct ext4_ext_cursor **ncurp, int *mergedp)
{
	int ret;
	bool nosib;
	int merged = 0;
	uint16_t nritems;
	uint16_t snritems;
	struct ext4_ext_cursor *ncur = NULL;
	struct ext4_extent_header *hdr;
	struct ext4_extent_header *shdr;

	*ncurp = NULL;
	*mergedp = 0;

	ret = ext4_ext_right_sibling(cur, depth, &ncur, &nosib);
	if (ret || nosib)
		goto out;

	hdr = cur->c_paths[depth].p_hdr;
	shdr = ncur->c_paths[depth].p_hdr;
	nritems = ext4_ext_header_entries(hdr);
	snritems = ext4_ext_header_entries(shdr);
	if (ext4_ext_may_merge(cur, depth) &&
	    nritems + snritems <= ext4_ext_header_max_entries(shdr)) {
		union ext4_extent_item *itemp = EXT_FIRST_ITEM(shdr);

		memmove(itemp + nritems, itemp, snritems * EXT4_EXT_ITEM_SIZE);
		memcpy(itemp, EXT_FIRST_ITEM(hdr),
		       nritems * EXT4_EXT_ITEM_SIZE);
		ext4_ext_header_set_entries(shdr, snritems + nritems);
		fs_mark_buffer_dirty(ncur->c_paths[depth].p_bcb);
		merged = 2;
	}
out:
	if (!merged && ncur) {
		ext4_ext_cursor_free(ncur);
		ncur = NULL;
	}
	*mergedp = merged;
	*ncurp = ncur;
	return ret;
}

/*
 * ext4_ext_try_merge -	Merge the node at given level to its sibling
 *
 * @cur:	Cursor to an extent tree
 * @depth:	The level where merging takes place at
 * @ncurp:	A place to store the address of new cursor at
 * @mergedp:	A place to return whether merging succeeds.
 * 		If merging to left succeeds, *@mergedp will be set to 1.
 * 		If merging to right succeeds, *@mergedp will be set to 2
 *
 * Return 0 if there is no error, or return values of ext4_ext_try_merge_left()
 * or ext4_ext_try_merge_right().
 */
static int
ext4_ext_try_merge(struct ext4_ext_cursor *cur, int depth,
		   struct ext4_ext_cursor **ncurp, int *mergedp)
{
	int ret;

	ret = ext4_ext_try_merge_left(cur, depth, ncurp, mergedp);
	if (ret || *mergedp)
		return ret;
	ret = ext4_ext_try_merge_right(cur, depth, ncurp, mergedp);
	return ret;
}

/*
 * ext4_ext_shrinkable -	Check if the tree can be shrank by one level
 *
 * @cur:		Cursor to an extent tree
 * @shrinkablep:	A place to return whether the tree can be shrank by one
 * 			level
 *
 * Return 0 if there is no error, ENOMEM if there is not enough memory space,
 * or return values of ext4_ext_right_sibling() or ext4_ext_lookup_extent().
 */
static int
ext4_ext_shrinkable(struct ext4_ext_cursor *cur, bool *shrinkablep)
{
	int ret = 0;
	int i = 0;
	int maxnritems;
	int nritems;
	int nnritems = 0;
	int rootdepth;
	struct ext4_extent_header *hdr;
	struct ext4_ext_cursor *ncur = NULL;
	bool shrinkable = false;

	rootdepth = ext4_ext_cursor_depth(cur);
	hdr = cur->c_root;

	if (!rootdepth)
		goto out;

	ncur = ext4_ext_cursor_alloc(cur->c_superblock, cur->c_root,
				     cur->c_fsinfo, cur->c_blocksz);
	if (!ncur)
		return ENOMEM;

	ret = ext4_ext_lookup_extent(ncur, 0, NULL);
	if (ret)
		goto out;

	maxnritems = ext4_ext_header_max_entries(hdr);
	nritems = ext4_ext_header_entries(hdr);

	for (i = 0; i < nritems; i++) {
		bool nosib;
		struct ext4_ext_cursor *tcur;
		struct ext4_extent_header *nhdr =
		
		nhdr = cur->c_paths[rootdepth - 1].p_hdr;

		nnritems += ext4_ext_header_entries(nhdr);
		ret =
		    ext4_ext_right_sibling(ncur, rootdepth - 1, &tcur, &nosib);
		if (ret)
			goto out;
		if (nosib) {
			if (tcur)
				ext4_ext_cursor_free(tcur);
			break;
		}
		ext4_ext_cursor_free(ncur);
		ncur = tcur;
	}
	if (nnritems <= maxnritems)
		shrinkable = true;

out:
	if (ncur)
		ext4_ext_cursor_free(ncur);
	*shrinkablep = shrinkable;
	return ret;
}

/*
 * __ext4_ext_shrink -	Shrink the tree by one level
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 if there is no error, ENOMEM if there is not enough memory space,
 * or return values of ext4_ext_right_sibling() or ext4_ext_lookup_extent().
 */
static int
__ext4_ext_shrink(struct ext4_ext_cursor *cur)
{
	int ret = 0;
	int i = 0;
	ssize_t ptr = -1;
	int maxnritems;
	int tnritems = 0;
	int nritems;
	struct ext4_extent_header *hdr;
	struct ext4_extent_header *thdr = NULL;
	int rootdepth;
	struct ext4_ext_cursor *ncur = NULL;
	union ext4_extent_item *titemp;
	struct ext4_extent_idx *idx;

	rootdepth = ext4_ext_cursor_depth(cur);
	if (!rootdepth)
		goto out;

	ncur = ext4_ext_cursor_alloc(cur->c_superblock, cur->c_root,
				     cur->c_fsinfo, cur->c_blocksz);
	if (!ncur)
		return ENOMEM;

	ret = ext4_ext_lookup_extent(ncur, 0, NULL);
	if (ret)
		goto out;

	hdr = cur->c_root;
	maxnritems = ext4_ext_header_max_entries(hdr);
	nritems = ext4_ext_header_entries(hdr);

	thdr = ext4_zalloc(EXT4_EXT_ROOT_SIZE);
	memcpy(thdr, hdr, sizeof(struct ext4_extent_header));
	ext4_ext_header_set_depth(thdr, rootdepth - 1);

	idx = EXT_FIRST_INDEX(hdr);
	titemp = EXT_FIRST_ITEM(thdr);

	for (i = 0; i < nritems; i++) {
		bool nosib;
		int nnritems;
		struct ext4_ext_cursor *tcur;
		struct ext4_extent_header *nhdr;
		union ext4_extent_item *nitemp;

		nhdr = cur->c_paths[rootdepth - 1].p_hdr;
		nitemp = EXT_FIRST_ITEM(nhdr);

		if (ext4_buf_blocknr(ncur->c_paths[rootdepth - 1].p_bcb) ==
		    ext4_buf_blocknr(cur->c_paths[rootdepth - 1].p_bcb)) {
			ptr = tnritems + cur->c_paths[rootdepth - 1].p_ptr;
		}

		nnritems = ext4_ext_header_entries(nhdr);
		tnritems += nnritems;
		ext4_assert(tnritems <= maxnritems);
		memcpy(titemp, nitemp, EXT4_EXT_ITEM_SIZE * nnritems);
		titemp += nnritems;

		ret =
		    ext4_ext_right_sibling(ncur, rootdepth - 1, &tcur, &nosib);
		if (ret)
			goto out;
		ext4_ext_cursor_free(ncur);
		ncur = NULL;
		if (nosib) {
			if (tcur)
				ext4_ext_cursor_free(tcur);
			break;
		}

		ncur = tcur;
	}
	ext4_ext_cursor_unpin(cur, rootdepth - 1, 2);

	for (i = 0; i < nritems; i++)
		cur->c_cursor_op.c_free_block_func(cur,
						   ext4_idx_block(idx + i));

	ext4_ext_header_set_entries(thdr, tnritems);
	memcpy(hdr, thdr, EXT4_EXT_ROOT_SIZE);

	rootdepth--;
	ext4_ext_cursor_reset_rootpath(cur);
	ext4_assert(ptr != -1);
	cur->c_paths[rootdepth].p_ptr = ptr;

out:
	if (thdr)
		ext4_free(thdr);
	if (ncur)
		ext4_ext_cursor_free(ncur);
	return ret;
}

/*
 * __ext4_ext_shrink -	Shrink the tree as short as possible
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 if there is no error, or return values of __ext4_ext_shrink()
 * or ext4_ext_shrinkable().
 */
static int
ext4_ext_tree_shrink(struct ext4_ext_cursor *cur)
{
	int ret;
	bool shrinkable;

	ret = ext4_ext_shrinkable(cur, &shrinkable);
	if (ret)
		return ret;

	while (shrinkable) {
		ret = __ext4_ext_shrink(cur);
		if (ret)
			break;

		ret = ext4_ext_shrinkable(cur, &shrinkable);
		if (ret)
			break;
	}
	return ret;
}

/*
 * ext4_ext_delete_leaf
 */
static int
ext4_ext_delete_leaf(struct ext4_ext_cursor *cur,
		     ext4_lblk_t tolblk,
		     int *stopp)
{
	int ret = 0;
	ssize_t ptr;
	uint16_t nritems;
	struct ext4_extent *ext;
	struct ext4_extent_header *hdr;

	*stopp = 0;

	while (1) {
		ptr = cur->c_paths[0].p_ptr;
		hdr = cur->c_paths[0].p_hdr;
		nritems = ext4_ext_header_entries(hdr);

		ext4_assert(nritems > 0);

		/*
		 * We have to stop if the extent's key
		 * is greater than @tolblk.
		 *
		 * TODO: What about being more precise?
		 */
		ext = EXT_FIRST_EXTENT(hdr) + ptr;
		if (ext4_ext_lblock(ext) > tolblk) {
			*stopp = 1;
			break;
		}

		/*
		 * Delete the extent pointed to by the path.
		 */
		ext4_ext_delete_item(cur, 0);
		nritems--;

		/*
		 * TODO: Unmap the underlying blocks!
		 */

		/*
		 * There are no more items we could delete.
		 */
		if (ptr >= nritems)
			break;
	}
	return ret;
}

/*
 * ext4_ext_delete_node
 */
static int
ext4_ext_delete_node(struct ext4_ext_cursor *cur,
		     int depth)
{
	int ret = 0;
	ssize_t ptr;
	ext4_fsblk_t blocknr;
	struct ext4_extent_idx *idx;
	struct ext4_extent_header *hdr;

	/*
	 * If we leave nothing in the node after
	 * deletion of an item, we free the block and
	 * delete the index of the node.
	 */

	/*
	 * Get the respective key of the node in the
	 * parent level
	 */
	hdr = cur->c_paths[depth].p_hdr;
	ext4_assert(ext4_ext_header_entries(hdr) > 0);
	ptr = cur->c_paths[depth].p_ptr;
	idx = EXT_FIRST_INDEX(hdr) + ptr;
	blocknr = ext4_idx_block(idx);

	/*
	 * Delete the index pointed to by the path.
	 */
	ext4_ext_delete_item(cur, depth);

	/*
	 * Free the block of it.
	 */
	cur->c_cursor_op.c_free_block_func(cur, blocknr);

out:
	return ret;
}


/*
 * ext4_ext_delete -	Delete an extent from an extent tree pointed to by
 * 			item pointer in the leaf. Nodes may be merged
 * 			together to balance the tree
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 on success, or ENOENT if there is no item to be deleted.
 * Cursor MUST be discarded after deletion.
 */
int
ext4_ext_delete_range(struct ext4_ext_cursor *cur,
		      ext4_lblk_t tolblk)
{
	int ret = 0;
	uint16_t nritems;
	int i = 0;
	int rootdepth;
	struct ext4_extent_header *hdr;

	rootdepth = ext4_ext_cursor_depth(cur);
	hdr = cur->c_paths[0].p_hdr;

	/*
	 * We return ENOENT as error if we found the buffer of the lowest
	 * level is unpinned, have no entries in it, or the pointer being
	 * out-of-range.
	 */
	if (!hdr || !ext4_ext_header_entries(hdr))
		return ENOENT;
	if (cur->c_paths[0].p_ptr == -1)
		return ENOENT;
	if (cur->c_paths[0].p_ptr >= ext4_ext_header_entries(hdr))
		return ENOENT;

	while (i <= rootdepth) {
		ssize_t ptr;

		if (!i) {
			int stop;

			ret = ext4_ext_delete_leaf(cur, tolblk,
						   &stop);
			if (ret)
				goto out;

			if (stop)
				break;
			/*
			 * Since there are no more items we could delete,
			 * we have to go to one level above to switch to the
			 * next leaf.
			 */
			i++;
			continue;
		}

		hdr = cur->c_paths[i - 1].p_hdr;
		nritems = ext4_ext_header_entries(hdr);

		/*
		 * Now we don't need the children path anymore.
		 */
		ext4_ext_cursor_unpin(cur, i - 1, 1);
		if (!nritems) {
			hdr = cur->c_paths[i].p_hdr;
			ptr = cur->c_paths[i].p_ptr;

			ret = ext4_ext_delete_node(cur, i);
			if (ret)
				goto out;

			nritems = ext4_ext_header_entries(hdr);
			if (ptr >= nritems) {
				/*
				 * Go to one level above
				 */
				i++;
			} else {
				ret = ext4_ext_reload_paths(cur, i);
				if (ret)
					goto out;
				/*
				 * Go to the bottom level (aka the leaf).
				 */
				i = 0;
			}
		} else {
			hdr = cur->c_paths[i].p_hdr;
			nritems = ext4_ext_header_entries(hdr);
			ptr = cur->c_paths[i].p_ptr;

			if (ptr == nritems - 1) {
				/*
				 * Go to one level above
				 */
				i++;
			} else {
				cur->c_paths[i].p_ptr = ++ptr;
				ret = ext4_ext_reload_paths(cur, i);
				if (ret)
					goto out;
				/*
				 * Go to the bottom level (aka the leaf).
				 */
				i = 0;
			}
		}
	}
	if (i < rootdepth) {
		/*
		 * We might have removed the leftmost key in the node,
		 * so we need to update the first key of the right
		 * sibling at every level until we meet a non-leftmost
		 * key.
		 */
		ext4_ext_update_index(cur, i, 1);
	} else {
		if (!ext4_ext_tree_empty(cur)) {
			/*
			 * Reload the cursor's path so that it points to
			 * a valid key again.
			 */
			ext4_ext_reload_paths(cur, i);
			ret = ext4_ext_tree_shrink(cur);
		} else {
			/*
			 * For empty root we need to make sure that the
			 * depth of the root level is 0.
			 */
			hdr = cur->c_root;
			ext4_ext_header_set_depth(hdr, 0);
			cur->c_cursor_op.c_root_dirty_func(cur);
			ext4_ext_cursor_unpin(cur, rootdepth, 1);
		}
	}

out:
	return ret;
}

/*
 * ext4_ext_delete -	Delete an extent from an extent tree pointed to by
 * 			item pointer in the leaf. Nodes may be merged
 * 			together to balance the tree
 *
 * @cur:	Cursor to an extent tree
 *
 * Return 0 on success, or ENOENT if there is no item to be deleted.
 * Cursor MUST be discarded after deletion.
 */
int
ext4_ext_delete(struct ext4_ext_cursor *cur)
{
	int ret = 0;
	uint16_t nritems;
	int i;
	int rootdepth;
	struct ext4_extent_header *hdr;

	rootdepth = ext4_ext_cursor_depth(cur);
	hdr = cur->c_paths[0].p_hdr;

	/*
	 * We return ENOENT as error if we found the buffer of the lowest
	 * level is unpinned, have no entries in it, or the pointer being
	 * out-of-range.
	 */
	if (!hdr || !ext4_ext_header_entries(hdr))
		return ENOENT;
	if (cur->c_paths[0].p_ptr == -1)
		return ENOENT;
	if (cur->c_paths[0].p_ptr >= ext4_ext_header_entries(hdr))
		return ENOENT;

	for (i = 0; i <= rootdepth; i++) {
		int merged = 0;
		ssize_t ptr;
		struct ext4_ext_cursor *ncur;
		struct ext4_extent_idx *idx;
		struct ext4_extent_header *uhdr;

		hdr = cur->c_paths[i].p_hdr;

		/*
		 * Delete the item pointed to by the path.
		 */
		ext4_ext_delete_item(cur, i);

		/*
		 * If we are deleting item at the root level,
		 * we are done.
		 */
		if (i == rootdepth)
			break;

		nritems = ext4_ext_header_entries(hdr);
		if (nritems) {
			/*
			 * Try to merge the node with left sibling or
			 * right sibling.
			 */
			ret = ext4_ext_try_merge(cur, i, &ncur, &merged);
			if (ret)
				goto out;

			if (merged == 1) {
				ext4_assert(ncur);

				/*
				 * After merging to left sibling,
				 * we need not to update the first key of the
				 * left sibling at every level.
				 */

				/*
				 * Throw away the cursor to sibling.
				 */
				ext4_ext_cursor_free(ncur);
			} else if (merged == 2) {
				ext4_assert(ncur);

				/*
				 * After merging to right sibling,
				 * we need to update the first key of the
				 * right sibling at every level until we
				 * meet a non-leftmost key.
				 */
				ext4_ext_update_index(ncur, i, 0);

				/*
				 * Throw away the cursor to sibling.
				 */
				ext4_ext_cursor_free(ncur);
			} else {
				/*
				 * No merge happens, so do nothing.
				 */
				ext4_assert(!ncur);
				break;
			}
		}
		/*
		 * If we have merged two nodes into one, or we leave
		 * nothing in the node after deletion of an item,
		 * we free the block of the node.
		 *
		 * At the next iteration we delete the key of the node.
		 */

		/*
		 * Get the respective key in parent node.
		 */
		uhdr = cur->c_paths[i + 1].p_hdr;
		ptr = cur->c_paths[i + 1].p_ptr;
		idx = EXT_FIRST_INDEX(uhdr) + ptr;

		/*
		 * Unpin the buffer of this node, and free
		 * the block of it.
		 */
		ext4_ext_cursor_unpin(cur, i, 1);
		cur->c_cursor_op.c_free_block_func(cur, ext4_idx_block(idx));
	}
	if (i < rootdepth) {
		/*
		 * We might have removed the leftmost key in the node,
		 * so we need to update the first key of the right
		 * sibling at every level until we meet a non-leftmost
		 * key.
		 */
		ext4_ext_update_index(cur, i, 0);
	} else {
		if (!ext4_ext_tree_empty(cur)) {
			/*
			 * Reload the cursor's path so that it points to
			 * a valid key again.
			 */
			ext4_ext_reload_paths(cur, i);
			ret = ext4_ext_tree_shrink(cur);
		} else {
			/*
			 * For empty root we need to make sure that the
			 * depth of the root level is 0.
			 */
			hdr = cur->c_root;
			ext4_ext_header_set_depth(hdr, 0);
			cur->c_cursor_op.c_root_dirty_func(cur);
			ext4_ext_cursor_unpin(cur, rootdepth, 1);
		}
	}

out:
	return ret;
}


/*
 * ext4_ext_init_i_blocks -	Initialize the root of a new extent tree
 */
void
ext4_ext_init_i_blocks(struct ext4_extent_header *hdr)
{
	ext4_ext_header_set_magic(hdr);
	ext4_ext_header_set_depth(hdr, 0);
	ext4_ext_header_set_max_entries(hdr, ext4_ext_root_maxitems());
	ext4_ext_header_set_entries(hdr, 0);
	ext4_ext_header_set_generation(hdr, 0);
}
