#ifndef _BUFFER_H
#define _BUFFER_H

#include <stddef.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>

#define USE_AIO
#ifdef USE_AIO
#include <aio.h>
#include <signal.h>
#endif

#include "kerncompat.h"
#include "list.h"
#include "rbtree.h"

#define READ 0
#define WRITE 1

#define might_sleep()
enum bh_state_bits {
	BH_Uptodate,      /* Contains valid data */
	BH_Dirty,	 /* Is dirty */
	BH_Verified,	 /* Is verified */
	BH_Lock,	  /* Is locked */
	BH_Req,		  /* Has been submitted for I/O */
	BH_Uptodate_Lock, /* Used by the first bh in a page, to serialise
			   * IO completion of other buffers in the page
			   */
	BH_Mapped,	   /* Has a disk mapping */
	BH_New,		     /* Disk mapping was newly created by get_block */
	BH_Async_Read,       /* Is under end_buffer_async_read I/O */
	BH_Async_Write,      /* Is under end_buffer_async_write I/O */
	BH_Delay,	    /* Buffer is not yet allocated on disk */
	BH_Boundary,	 /* Block is followed by a discontiguity */
	BH_Write_EIO,	/* I/O error on write */
	BH_Unwritten,	/* Buffer is allocated on disk but not written */
	BH_Quiet,	    /* Buffer Error Prinks to be quiet */
	BH_Meta,	     /* Buffer contains metadata */
	BH_Prio,	     /* Buffer should be submitted with REQ_PRIO */
	BH_Defer_Completion, /* Defer AIO completion to workqueue */
	BH_PrivateStart,     /* not a state bit, but the first bit available
	      * for private allocation by other entities
	      */
	BH_Ordered,
	BH_Eopnotsupp
};

struct super_block;
struct buffer_head;
struct block_device {
	int bd_fd;
	unsigned long bd_flags; /* flags */
	struct super_block *bd_super;

	int bd_nr_free;
	pthread_mutex_t bd_bh_free_lock;
	struct list_head bd_bh_free;

	pthread_mutex_t bd_bh_dirty_lock;
	struct list_head bd_bh_dirty;

	pthread_mutex_t bd_bh_ioqueue_lock;
	struct list_head bd_bh_ioqueue;

	pthread_mutex_t bd_bh_root_lock;
	struct rb_root bd_bh_root;

	pthread_t bd_bh_io_thread;
	pthread_t bd_bh_writeback_thread;
	int bd_bh_io_wakeup_fd[2];
	int bd_bh_writeback_wakeup_fd[2];
};

struct super_block
{
	size_t s_blocksize;
	int s_blocksize_bits;
	struct block_device *s_bdev;
	void *s_fs_info;
};

typedef void(bh_end_io_t)(struct buffer_head *, int);

/*
 * Historically, a buffer_head was used to map a single block
 * within a page, and of course as the unit of I/O through the
 * filesystem and block layers.  Nowadays the basic I/O unit
 * is the bio, and buffer_heads are used for extracting block
 * mappings (via a get_block_t call), for tracking state within
 * a page (via a page_mapping) and for wrapping bio submission
 * for backward compatibility reasons (e.g. submit_bh).
 */
typedef int atomic_t;

struct buffer_head
{
	unsigned long b_state; /* buffer state bitmap (see above) */

	uint64_t b_blocknr; /* start block number */
	size_t b_size;      /* size of mapping */
	char *b_data;       /* pointer to data within the page */
	char *b_page;       /* pointer to data within the page */

#ifdef USE_AIO
	struct aiocb b_aiocb;
	sem_t b_event;
#endif

	struct block_device *b_bdev;
	bh_end_io_t *b_end_io; /* I/O completion */
	void *b_private;       /* reserved for b_end_io */

	atomic_t b_count; /* users using this buffer_head */
	pthread_mutex_t b_lock;

	struct list_head b_io_list;
	struct list_head b_dirty_list;
	struct list_head b_freelist;
	struct rb_node b_rb_node;
};

/*
 * macro tricks to expand the set_buffer_foo(), clear_buffer_foo()
 * and buffer_foo() functions.
 */
#define BUFFER_FNS(bit, name)                                                  \
	static inline void set_buffer_##name(struct buffer_head *bh)           \
	{                                                                      \
		__set_bit(BH_##bit, &(bh)->b_state);                           \
	}                                                                      \
	static inline void clear_buffer_##name(struct buffer_head *bh)         \
	{                                                                      \
		__clear_bit(BH_##bit, &(bh)->b_state);                         \
	}                                                                      \
	static inline int buffer_##name(const struct buffer_head *bh)          \
	{                                                                      \
		return test_bit(BH_##bit, &(bh)->b_state);                     \
	}

/*
 * test_set_buffer_foo() and test_clear_buffer_foo()
 */
#define TAS_BUFFER_FNS(bit, name)                                              \
	static inline int test_set_buffer_##name(struct buffer_head *bh)       \
	{                                                                      \
		return __test_and_set_bit(BH_##bit, &(bh)->b_state);           \
	}                                                                      \
	static inline int test_clear_buffer_##name(struct buffer_head *bh)     \
	{                                                                      \
		return __test_and_clear_bit(BH_##bit, &(bh)->b_state);         \
	}

/*
 * Emit the buffer bitops functions.   Note that there are also functions
 * of the form "mark_buffer_foo()".  These are higher-level functions which
 * do something in addition to setting a b_state bit.
 */
BUFFER_FNS(Uptodate, uptodate)
BUFFER_FNS(Verified, verified)
BUFFER_FNS(Dirty, dirty)
TAS_BUFFER_FNS(Dirty, dirty)
BUFFER_FNS(Lock, locked)
TAS_BUFFER_FNS(Lock, locked)
BUFFER_FNS(Req, req)
TAS_BUFFER_FNS(Req, req)
BUFFER_FNS(Mapped, mapped)
BUFFER_FNS(New, new)
BUFFER_FNS(Meta, meta)
BUFFER_FNS(Prio, prio)
BUFFER_FNS(Async_Read, async_read)
BUFFER_FNS(Async_Write, async_write)
TAS_BUFFER_FNS(Async_Write, async_write)
BUFFER_FNS(Delay, delay)
BUFFER_FNS(Boundary, boundary)
BUFFER_FNS(Write_EIO, write_io_error)
BUFFER_FNS(Ordered, ordered)
BUFFER_FNS(Eopnotsupp, eopnotsupp)
BUFFER_FNS(Unwritten, unwritten)

static inline int trylock_buffer(struct buffer_head *bh)
{
	return !pthread_mutex_trylock(&bh->b_lock);
}

static inline void lock_buffer(struct buffer_head *bh)
{
	might_sleep();
	if (!trylock_buffer(bh))
		pthread_mutex_lock(&bh->b_lock);
}

static inline void unlock_buffer(struct buffer_head *bh)
{
	pthread_mutex_unlock(&bh->b_lock);
}

static inline void get_bh(struct buffer_head *bh)
{
	__sync_fetch_and_add(&bh->b_count, 1);
}

static inline void put_bh(struct buffer_head *bh)
{
	__sync_fetch_and_sub(&bh->b_count, 1);
}

static inline int put_bh_and_read(struct buffer_head *bh)
{
	return __sync_sub_and_fetch(&bh->b_count, 1);
}

struct buffer_head *__getblk(struct block_device *, uint64_t, int);
static inline struct buffer_head *sb_getblk(struct super_block *super,
					    uint64_t block)
{
	return __getblk(super->s_bdev, block, super->s_blocksize);
}

int device_open(const char *path);

struct block_device *bdev_alloc(int fd, int blocksize_bits);
void bdev_free(struct block_device *bdev);
struct buffer_head *buffer_alloc(struct block_device *bdev, uint64_t block,
				 int page_size);
void brelse(struct buffer_head *bh);
int bh_submit_read(struct buffer_head *bh);
void wait_on_buffer(struct buffer_head *bh);

uint64_t simple_balloc(struct super_block *device, unsigned long blockcnt);
uint64_t device_size(struct block_device *bdev);

#endif
