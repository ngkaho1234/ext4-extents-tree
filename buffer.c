/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>

#include "buffer.h"

static int buffer_free_threshold = 90000;
static int buffer_dirty_threshold = 9;
static int buffer_dirty_count = 0;
static int buffer_writeback_ms = 10000;

/*
 * Pseduo device reading routine.
 * Actually we are reading data from a file.
 */
int pread_wrapper(int disk_fd, void *p, size_t size, off_t where)
{
#if defined(__FreeBSD__) && !defined(__APPLE__)
	/* FreeBSD needs to read aligned whole blocks.
	 * TODO: Check what is a safe block size.
	 */
	static __thread uint8_t block[PREAD_BLOCK_SIZE];
	off_t first_offset = where % PREAD_BLOCK_SIZE;
	int ret = 0;

	if (first_offset) {
		/* This is the case if the read doesn't start on a block boundary.
		 * We still need to read the whole block and we do, but we only copy to
		 * the out pointer the bytes that where actually asked for.  In this
		 * case first_offset is the offset into the block. */
		int pread_ret = pread(disk_fd, block, PREAD_BLOCK_SIZE, where - first_offset);
		ASSERT(pread_ret == PREAD_BLOCK_SIZE);

		size_t first_size = MIN(size, (size_t)(PREAD_BLOCK_SIZE - first_offset));
		memcpy(p, block + first_offset, first_size);
		p += first_size;
		size -= first_size;
		where += first_size;
		ret += first_size;

		if (!size) return ret;
	}

	ASSERT(where % PREAD_BLOCK_SIZE == 0);

	size_t mid_read_size = (size / PREAD_BLOCK_SIZE) * PREAD_BLOCK_SIZE;
	if (mid_read_size) {
		int pread_ret_mid = pread(disk_fd, p, mid_read_size, where);
		ASSERT((size_t)pread_ret_mid == mid_read_size);

		p += mid_read_size;
		size -= mid_read_size;
		where += mid_read_size;
		ret += mid_read_size;

		if (!size) return ret;
	}

	ASSERT(size < PREAD_BLOCK_SIZE);

	int pread_ret_last = pread(disk_fd, block, PREAD_BLOCK_SIZE, where);
	ASSERT(pread_ret_last == PREAD_BLOCK_SIZE);

	memcpy(p, block, size);

	return ret + size;
#else
	return pread(disk_fd, p, size, where);
#endif
}

#ifndef USE_AIO

static int pwrite_wrapper(int disk_fd, const void *p, size_t size, off_t where)
{
#if defined(__FreeBSD__) && !defined(__APPLE__)
	/* FreeBSD needs to read aligned whole blocks.
	 * TODO: Check what is a safe block size.
	 */
	static __thread uint8_t block[PREAD_BLOCK_SIZE];
	off_t first_offset = where % PREAD_BLOCK_SIZE;
	int ret = 0;

	if (first_offset) {
		/* This is the case if the read doesn't start on a block boundary.
		 * We still need to read the whole block and we do, but we only copy to
		 * the out pointer the bytes that where actually asked for.  In this
		 * case first_offset is the offset into the block. */
		int pread_ret = pread(disk_fd, block, PREAD_BLOCK_SIZE, where - first_offset);
		ASSERT(pread_ret == PREAD_BLOCK_SIZE);
		size_t first_size = MIN(size, (size_t)(PREAD_BLOCK_SIZE - first_offset));
		memcpy(block + first_offset, p, first_size);

		pread_ret = pwrite(disk_fd, block, PREAD_BLOCK_SIZE, where - first_offset);
		p += first_size;
		size -= first_size;
		where += first_size;
		ret += first_size;

		if (!size) return ret;
	}

	ASSERT(where % PREAD_BLOCK_SIZE == 0);

	size_t mid_write_size = (size / PREAD_BLOCK_SIZE) * PREAD_BLOCK_SIZE;
	if (mid_write_size) {
		int pwrite_ret_mid = pwrite(disk_fd, p, mid_write_size, where);
		ASSERT((size_t)pwrite_ret_mid == mid_write_size);

		p += mid_write_size;
		size -= mid_write_size;
		where += mid_write_size;
		ret += mid_write_size;

		if (!size) return ret;
	}

	ASSERT(size < PREAD_BLOCK_SIZE);

	int pread_ret_last = pread(disk_fd, block, PREAD_BLOCK_SIZE, where);
	ASSERT(pread_ret_last == PREAD_BLOCK_SIZE);

	memcpy(block, p, size);
	pread_ret_last = pwrite(disk_fd, block, PREAD_BLOCK_SIZE, where);

	return ret + size;
#else
	return pwrite(disk_fd, p, size, where);
#endif
}

static int device_read(int fd, uint64_t block, int count, int blk_size,
		       void *buf)
{
	int ret = pread_wrapper(fd, buf, blk_size * count, block * blk_size);
	if (ret < 0) {
		return -1;
	}

	return ret;
}

/*
 * Pseduo device writing routine.
 * Write @buf into the device file / a file.
 */
static int device_write(int fd, uint64_t block, int count, int blk_size,
			void *buf)
{
	int ret = pwrite_wrapper(fd, buf, blk_size * count, block * blk_size);
	if (ret < 0) {
		return -1;
	}
	return ret;
}

#endif

int device_open(const char *path)
{
    int disk_fd = open(path, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR |
		    			     S_IRGRP |
					     S_IROTH);
    if (disk_fd < 0) {
        return -errno;
    }

    return disk_fd;
}

static struct buffer_head *__buffer_search(struct rb_root *root,
					   uint64_t blocknr)
{
	struct rb_node *new = root->rb_node;

	/* Figure out where to put new node */
	while (new) {
		struct buffer_head *bh =
		    container_of(new, struct buffer_head, b_rb_node);
		int64_t result = blocknr - bh->b_blocknr;

		if (result < 0)
			new = new->rb_left;
		else if (result > 0)
			new = new->rb_right;
		else
			return bh;
	}

	return NULL;
}

static int buffer_blocknr_cmp(struct rb_node *a, struct rb_node *b)
{
	struct buffer_head *a_bh, *b_bh;
	a_bh = container_of(a, struct buffer_head, b_rb_node);
	b_bh = container_of(b, struct buffer_head, b_rb_node);

	if ((int64_t)(a_bh->b_blocknr - b_bh->b_blocknr) < 0)
		return -1;
	if ((int64_t)(a_bh->b_blocknr - b_bh->b_blocknr) > 0)
		return 1;
	return 0;
}

static struct buffer_head *buffer_search(struct block_device *bdev,
					 uint64_t blocknr)
{
	struct rb_root *root;
	struct buffer_head *bh;
	root = &bdev->bd_bh_root;
	pthread_mutex_lock(&bdev->bd_bh_root_lock);
	bh = __buffer_search(root, blocknr);
	pthread_mutex_unlock(&bdev->bd_bh_root_lock);

	return bh;
}

static void buffer_insert(struct block_device *bdev,
			  struct buffer_head *bh)
{
	pthread_mutex_lock(&bdev->bd_bh_root_lock);
	rb_insert(&bdev->bd_bh_root, &bh->b_rb_node, buffer_blocknr_cmp);
	pthread_mutex_unlock(&bdev->bd_bh_root_lock);
}

static void __buffer_remove(struct block_device *bdev,
			  struct buffer_head *bh)
{
	rb_erase(&bh->b_rb_node, &bdev->bd_bh_root);
}


#ifndef USE_AIO
static void *buffer_io_thread(void *arg);
#endif

static void *buffer_writeback_thread(void *arg);

struct block_device *bdev_alloc(int fd, int blocksize_bits)
{
	struct block_device *bdev;
	struct super_block *super;

	bdev = kmalloc(sizeof(struct block_device) + sizeof(struct super_block),
		       GFP_NOFS);
	memset(bdev, 0,
	       sizeof(struct block_device) + sizeof(struct super_block));
	super = (struct super_block *)(bdev + 1);

	bdev->bd_fd = fd;
	bdev->bd_flags = 0;
	bdev->bd_super = super;

	INIT_LIST_HEAD(&bdev->bd_bh_free);
	INIT_LIST_HEAD(&bdev->bd_bh_dirty);
#ifndef USE_AIO
	INIT_LIST_HEAD(&bdev->bd_bh_ioqueue);
#endif
	pthread_mutex_init(&bdev->bd_bh_free_lock, NULL);
	pthread_mutex_init(&bdev->bd_bh_dirty_lock, NULL);
#ifndef USE_AIO
	pthread_mutex_init(&bdev->bd_bh_ioqueue_lock, NULL);
#endif
	pthread_mutex_init(&bdev->bd_bh_root_lock, NULL);

	super->s_blocksize_bits = blocksize_bits;
	super->s_blocksize = 1 << super->s_blocksize_bits;
	super->s_bdev = bdev;

	pipe(bdev->bd_bh_writeback_wakeup_fd);
	pthread_create(&bdev->bd_bh_writeback_thread, NULL,
			buffer_writeback_thread, bdev);

#ifndef USE_AIO
	pipe(bdev->bd_bh_io_wakeup_fd);
	pthread_create(&bdev->bd_bh_io_thread, NULL,
			buffer_io_thread, bdev);
#endif

	return bdev;
}


static void bdev_writeback_thread_notify(struct block_device *bdev)
{
	signed char test_byte = 1;
	write(bdev->bd_bh_writeback_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static void bdev_writeback_thread_notify_exit(struct block_device *bdev)
{
	signed char test_byte = -1;
	write(bdev->bd_bh_writeback_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static signed char bdev_writeback_thread_read_notify(struct block_device *bdev)
{
	signed char test_byte = 0;
	read(bdev->bd_bh_writeback_wakeup_fd[0], &test_byte, sizeof(test_byte));
	return test_byte;
}

static int bdev_is_notify_exiting(signed char byte)
{
	if (byte < 0)
		return 1;
	return 0;
}

#ifndef USE_AIO

static void bdev_io_thread_notify(struct block_device *bdev)
{
	signed char test_byte = 1;
	write(bdev->bd_bh_io_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static void bdev_io_thread_notify_exit(struct block_device *bdev)
{
	signed char test_byte = -1;
	write(bdev->bd_bh_io_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static signed char bdev_io_thread_read_notify(struct block_device *bdev)
{
	signed char test_byte = 0;
	read(bdev->bd_bh_io_wakeup_fd[0], &test_byte, sizeof(test_byte));
	return test_byte;
}

#endif

static int sync_dirty_buffer(struct buffer_head *bh);
static void detach_bh_from_freelist(struct buffer_head *bh);
static void buffer_free(struct buffer_head *bh);

void bdev_free(struct block_device *bdev)
{
	struct rb_node *node;

	bdev_writeback_thread_notify_exit(bdev);
	pthread_join(bdev->bd_bh_writeback_thread, NULL);

#ifndef USE_AIO
	bdev_io_thread_notify_exit(bdev);
	pthread_join(bdev->bd_bh_io_thread, NULL);
#endif
	
	pthread_mutex_lock(&bdev->bd_bh_root_lock);
	while ((node = rb_first(&bdev->bd_bh_root))) {
		struct buffer_head *bh = rb_entry(
		    node, struct buffer_head, b_rb_node);
		wait_on_buffer(bh);
		detach_bh_from_freelist(bh);
		__buffer_remove(bdev, bh);
		buffer_free(bh);
	}
	pthread_mutex_unlock(&bdev->bd_bh_root_lock);

	if (bdev->bd_nr_free != 0)
		fprintf(stderr, "bdev->bd_nr_free == %d", bdev->bd_nr_free);

#ifndef USE_AIO
	close(bdev->bd_bh_io_wakeup_fd[0]);
	close(bdev->bd_bh_io_wakeup_fd[1]);
#endif

	close(bdev->bd_bh_writeback_wakeup_fd[0]);
	close(bdev->bd_bh_writeback_wakeup_fd[1]);

	pthread_mutex_destroy(&bdev->bd_bh_free_lock);
	pthread_mutex_destroy(&bdev->bd_bh_dirty_lock);
#ifndef USE_AIO
	pthread_mutex_destroy(&bdev->bd_bh_ioqueue_lock);
#endif
	pthread_mutex_destroy(&bdev->bd_bh_root_lock);

	kfree(bdev);
}


static void sync_writeback_buffers(struct block_device *bdev)
{
	if (buffer_dirty_count > buffer_dirty_threshold)
		bdev_writeback_thread_notify(bdev);
}


struct buffer_head *buffer_alloc(struct block_device *bdev, uint64_t block,
				 int page_size)
{
	struct buffer_head *bh;
	bh = kmalloc(sizeof(struct buffer_head) + page_size, GFP_NOFS);
	if (!bh)
		return NULL;

	memset(bh, 0, sizeof(struct buffer_head));
	bh->b_bdev = bdev;
	bh->b_data = (char *)(bh + 1);
	bh->b_size = page_size;
	bh->b_blocknr = block;
	bh->b_count = 0;
	bh->b_page = NULL;

	sem_init(&bh->b_event, 0, 1);

	pthread_mutex_init(&bh->b_lock, NULL);
	INIT_LIST_HEAD(&bh->b_freelist);
	INIT_LIST_HEAD(&bh->b_dirty_list);

#ifndef USE_AIO
	INIT_LIST_HEAD(&bh->b_io_list);
#endif

	sync_writeback_buffers(bdev);

	return bh;
}

static void buffer_free(struct buffer_head *bh)
{
	sem_destroy(&bh->b_event);
	pthread_mutex_destroy(&bh->b_lock);

	if (bh->b_count != 0)
		fprintf(stderr, "bh: %p b_count != 0, my pid: %d", bh, getpid());

	kfree(bh);
}


static void
attach_bh_to_freelist(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	if (list_empty(&bh->b_freelist)) {
		pthread_mutex_lock(&bdev->bd_bh_free_lock);
		list_add_tail(&bh->b_freelist, &bh->b_bdev->bd_bh_free);
		bh->b_bdev->bd_nr_free++;
		pthread_mutex_unlock(&bdev->bd_bh_free_lock);
	}
}

static void
detach_bh_from_freelist(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	if (!list_empty(&bh->b_freelist)) {
		pthread_mutex_lock(&bdev->bd_bh_free_lock);
		list_del_init(&bh->b_freelist);
		bh->b_bdev->bd_nr_free--;
		pthread_mutex_unlock(&bdev->bd_bh_free_lock);
	}
}

static void
remove_first_bh_from_freelist(struct block_device *bdev)
{
	struct buffer_head *bh;

	pthread_mutex_lock(&bdev->bd_bh_free_lock);
	if (list_empty(&bdev->bd_bh_free)) {
		pthread_mutex_unlock(&bdev->bd_bh_free_lock);
		return;
	}
	bh = list_first_entry(&bdev->bd_bh_free,
			      struct buffer_head, b_freelist);
	list_del_init(&bh->b_freelist);
	bh->b_bdev->bd_nr_free--;
	pthread_mutex_unlock(&bdev->bd_bh_free_lock);

	pthread_mutex_lock(&bdev->bd_bh_root_lock);
	__buffer_remove(bdev, bh);
	pthread_mutex_unlock(&bdev->bd_bh_root_lock);
	buffer_free(bh);
}


static void move_buffer_to_writeback(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	pthread_mutex_lock(&bdev->bd_bh_dirty_lock);
	if (list_empty(&bh->b_dirty_list)) {
		list_add_tail(&bh->b_dirty_list, &bh->b_bdev->bd_bh_dirty);
		buffer_dirty_count++;
	}
	pthread_mutex_unlock(&bdev->bd_bh_dirty_lock);
}

static struct buffer_head *
remove_first_buffer_from_writeback(struct block_device *bdev)
{
	struct buffer_head *bh;

	pthread_mutex_lock(&bdev->bd_bh_dirty_lock);
	if (list_empty(&bdev->bd_bh_dirty)) {
		pthread_mutex_unlock(&bdev->bd_bh_dirty_lock);
		return NULL;
	}
	bh = list_first_entry(&bdev->bd_bh_dirty,
			      struct buffer_head, b_dirty_list);
	list_del_init(&bh->b_dirty_list);
	buffer_dirty_count--;
	pthread_mutex_unlock(&bdev->bd_bh_dirty_lock);

	return bh;
}

static void remove_buffer_from_writeback(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	pthread_mutex_lock(&bdev->bd_bh_dirty_lock);
	if (!list_empty(&bh->b_dirty_list)) {
		list_del_init(&bh->b_dirty_list);
		buffer_dirty_count--;
	}
	pthread_mutex_unlock(&bdev->bd_bh_dirty_lock);
}

#ifndef USE_AIO

static void add_buffer_to_ioqueue(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	pthread_mutex_lock(&bdev->bd_bh_ioqueue_lock);
	if (list_empty(&bh->b_io_list))
		list_add_tail(&bh->b_io_list, &bh->b_bdev->bd_bh_ioqueue);

	pthread_mutex_unlock(&bdev->bd_bh_ioqueue_lock);
}

static struct buffer_head *
remove_first_buffer_from_ioqueue(struct block_device *bdev)
{
	struct buffer_head *bh;

	pthread_mutex_lock(&bdev->bd_bh_ioqueue_lock);
	if (list_empty(&bdev->bd_bh_ioqueue)) {
		pthread_mutex_unlock(&bdev->bd_bh_ioqueue_lock);
		return NULL;
	}
	bh = list_first_entry(&bdev->bd_bh_ioqueue,
			      struct buffer_head, b_io_list);
	list_del_init(&bh->b_io_list);
	pthread_mutex_unlock(&bdev->bd_bh_ioqueue_lock);

	return bh;
}

#endif


static void try_to_drop_buffers(struct block_device *bdev)
{
	while (bdev->bd_nr_free > buffer_free_threshold) {
		remove_first_bh_from_freelist(bdev);
	}
}

static void reclaim_buffer(struct buffer_head *bh)
{
	try_to_drop_buffers(bh->b_bdev);
	attach_bh_to_freelist(bh);
}

#ifdef USE_AIO
#define IO_SIGNAL SIGIO

void iocb_dispatch(union sigval value)
{
	struct buffer_head *bh = value.sival_ptr;
	int err;
	if (!bh)
		return;

	err = aio_error(&bh->b_aiocb);
	if (err < 0)
		bh->b_end_io(bh, 0);
	else
		bh->b_end_io(bh, 1);
}

#endif

void wait_on_buffer(struct buffer_head *bh)
{
	/*const struct aiocb const *aiocb_list[2] = {&bh->b_aiocb, NULL};*/
	/*aio_suspend(aiocb_list, 1, NULL);*/
	sem_wait(&bh->b_event);
	sem_post(&bh->b_event);
}

/*
 * Submit an IO request.
 * FIXME: any calls to submit_bh are supposed to be non-blocking.
 */
int __submit_bh(int is_write, struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;

	if (is_write == 0) {
#ifndef USE_AIO
		int ret;
		sem_wait(&bh->b_event);
		ret = device_read(bdev->bd_fd, bh->b_blocknr, 1,
				   bh->b_size, bh->b_data);
		if (ret < 0)
			bh->b_end_io(bh, 0);
		else
			bh->b_end_io(bh, 1);
#else
		bh->b_aiocb.aio_fildes = bdev->bd_fd;
		bh->b_aiocb.aio_buf = bh->b_data;
		bh->b_aiocb.aio_nbytes = bh->b_size;
		bh->b_aiocb.aio_reqprio = 0;
		bh->b_aiocb.aio_offset = bh->b_blocknr * bh->b_size;
		bh->b_aiocb.aio_sigevent.sigev_notify = SIGEV_THREAD;
		bh->b_aiocb.aio_sigevent.sigev_notify_function = iocb_dispatch;
		bh->b_aiocb.aio_sigevent.sigev_value.sival_ptr = bh;
		sem_wait(&bh->b_event);
		aio_read(&bh->b_aiocb);
#endif
	} else {
#ifndef USE_AIO
		int ret;
		sem_wait(&bh->b_event);
		ret = device_write(bdev->bd_fd, bh->b_blocknr, 1,
				   bh->b_size, bh->b_data);
		if (ret < 0)
			bh->b_end_io(bh, 0);
		else
			bh->b_end_io(bh, 1);
#else
		bh->b_aiocb.aio_fildes = bdev->bd_fd;
		bh->b_aiocb.aio_buf = bh->b_data;
		bh->b_aiocb.aio_nbytes = bh->b_size;
		bh->b_aiocb.aio_reqprio = 0;
		bh->b_aiocb.aio_offset = bh->b_blocknr * bh->b_size;
		bh->b_aiocb.aio_sigevent.sigev_notify = SIGEV_THREAD;
		bh->b_aiocb.aio_sigevent.sigev_notify_function = iocb_dispatch;
		bh->b_aiocb.aio_sigevent.sigev_value.sival_ptr = bh;
		sem_wait(&bh->b_event);
		aio_write(&bh->b_aiocb);
#endif
	}

	return 0;
}

int submit_bh(int is_write, struct buffer_head *bh)
{
#ifdef USE_AIO
	return __submit_bh(is_write, bh);
#else
	if (is_write)
		set_buffer_async_write(bh);

	add_buffer_to_ioqueue(bh);
	bdev_io_thread_notify(bh->b_bdev);
	
	return 0;
#endif
}

void after_buffer_sync(struct buffer_head *bh, int uptodate)
{
	if (uptodate)
		set_buffer_uptodate(bh);

	put_bh(bh);
	remove_buffer_from_writeback(bh);
	clear_buffer_dirty(bh);
	attach_bh_to_freelist(bh);
	unlock_buffer(bh);
	sem_post(&bh->b_event);
}

void after_buffer_write(struct buffer_head *bh, int uptodate)
{
	if (uptodate)
		set_buffer_uptodate(bh);

	put_bh(bh);
	remove_buffer_from_writeback(bh);
	clear_buffer_dirty(bh);
	unlock_buffer(bh);
	sem_post(&bh->b_event);
}

void after_submit_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate)
		set_buffer_uptodate(bh);

	put_bh(bh);
	unlock_buffer(bh);
	sem_post(&bh->b_event);
}

int bh_submit_read(struct buffer_head *bh)
{
	int ret;

	lock_buffer(bh);
	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}

	get_bh(bh);
	clear_buffer_dirty(bh);
	remove_buffer_from_writeback(bh);
	bh->b_end_io = after_submit_read;
	ret = submit_bh(READ, bh);
	return ret;
}

static int sync_dirty_buffer(struct buffer_head *bh)
{
	int ret = 0;

	if (!trylock_buffer(bh))
		return ret;

	if (bh->b_count < 1 && buffer_dirty(bh)) {
		get_bh(bh);
		bh->b_end_io = after_buffer_sync;
		ret = submit_bh(WRITE, bh);
	} else {
		unlock_buffer(bh);
	}
	return ret;
}

int write_dirty_buffer(struct buffer_head *bh)
{
	int ret = 0;

	if (!trylock_buffer(bh))
		return ret;

	if (buffer_dirty(bh)) {
		get_bh(bh);
		bh->b_end_io = after_buffer_write;
		ret = submit_bh(WRITE, bh);
	} else {
		unlock_buffer(bh);
	}
	return ret;
}

struct buffer_head *__getblk(struct block_device *bdev, uint64_t block,
			     int bsize)
{
	struct buffer_head *bh;

	bh = buffer_search(bdev, block);
	if (bh) {
		detach_bh_from_freelist(bh);
		remove_buffer_from_writeback(bh);
		get_bh(bh);
		return bh;
	}
	bh = buffer_alloc(bdev, block, bsize);
	if (bh == NULL)
		return NULL;

	buffer_insert(bdev, bh);

	get_bh(bh);
	return bh;
}

/*
 * Release the buffer_head.
 */
void brelse(struct buffer_head *bh)
{
	int refcount;
	if (bh == NULL)
		return;
	refcount = put_bh_and_read(bh);
	if (refcount >= 1)
		goto out;
	assert(refcount == 0);

	if (!buffer_dirty(bh))
		reclaim_buffer(bh);
	else
		move_buffer_to_writeback(bh);
out:
	return;
}


static void try_to_sync_buffers(struct block_device *bdev)
{
	while (1) {
		struct buffer_head *cur;
		cur = remove_first_buffer_from_writeback(bdev);
		if (cur) {
			sync_dirty_buffer(cur);
			wait_on_buffer(cur);
		} else
			break;

	}
}

static void *buffer_writeback_thread(void *arg)
{
	struct epoll_event epev = {0};
	struct block_device *bdev = arg;
	int epfd = epoll_create(1);
	if (epfd < 0)
		return NULL;

	epev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, bdev->bd_bh_writeback_wakeup_fd[0], &epev);

	while (1) {
		int ret;
		ret = epoll_wait(epfd, &epev, 1, buffer_writeback_ms);
		if (ret > 0) {
			/* We got an nofication. */
			signed char command;
			command = bdev_writeback_thread_read_notify(bdev);
			try_to_sync_buffers(bdev);
			if (bdev_is_notify_exiting(command))
				break;
			
			continue;
		}
		if (ret == 0) {
			/* just flush out the dirty data. */
			try_to_sync_buffers(bdev);
		}
		if (ret < 0 && errno != EINTR)
			break;

	}
	close(epfd);
	return NULL;
}

#ifndef USE_AIO

static void try_to_perform_io(struct block_device *bdev)
{
	while (1) {
		struct buffer_head *cur;
		cur = remove_first_buffer_from_ioqueue(bdev);
		if (cur) {
			__submit_bh(test_clear_buffer_async_write(cur),
				    cur);
		} else
			break;

	}
}

static void *buffer_io_thread(void *arg)
{
	struct epoll_event epev = {0};
	struct block_device *bdev = arg;
	int epfd = epoll_create(1);
	if (epfd < 0)
		return NULL;

	epev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, bdev->bd_bh_io_wakeup_fd[0], &epev);

	while (1) {
		int ret;
		ret = epoll_wait(epfd, &epev, 1, -1);
		if (ret > 0) {
			/* We got an nofication. */
			signed char command;
			command = bdev_io_thread_read_notify(bdev);

			try_to_perform_io(bdev);
			if (bdev_is_notify_exiting(command))
				break;

		}
		if (ret < 0 && errno != EINTR)
			break;

	}
	close(epfd);
	return NULL;
}

#endif

uint64_t simple_balloc(struct super_block *device, unsigned long blockcnt)
{
	struct stat64 buf;
	if(fstat64(device->s_bdev->bd_fd, &buf)) {
		perror("fstat64");
		printf("file size: %" PRIu64 "\n", buf.st_size);
		return 0;
	}
	if (posix_fallocate(device->s_bdev->bd_fd, buf.st_size, (uint64_t)blockcnt * device->s_blocksize)) {
		perror("fallocate64");
		printf("file size: %" PRIu64 ", request blockcnt: %lu\n", buf.st_size, blockcnt);
		return 0;
	}

	return buf.st_size / device->s_blocksize;
}

uint64_t device_size(struct block_device *bdev)
{
	struct stat64 buf;
	if(fstat64(bdev->bd_fd, &buf)) {
		perror("fstat64");
		printf("file size: %" PRIu64 "\n", buf.st_size);
		return 0;
	}

	return buf.st_size;
}
