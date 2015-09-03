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
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include "buffer.h"
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>

static int buffer_free_threshold = 90000;
static int buffer_dirty_threshold = 9;
static int buffer_dirty_count = 0;
static int buffer_writeback_ms = 1000;

/*
 * Pseduo device opening routine.
 * As we do still need more test on this.
 */
int device_open(char *file)
{
	int fd;
	fd = open(file, O_RDWR | O_CREAT, 0666);

	if (fd < 0) {
		return -1;
	}
	return fd;
}

/*
 * Pseduo device reading routine.
 * Actually we are reading data from a file.
 */
static int device_read(int fd, uint64_t block, int count, int blk_size,
		       void *buf)
{
	int ret;
	static int rdcount;
	uint64_t off, seek_ret;

	off = block * blk_size;
	/*
	 * lseek64 is a wrap-up libcall of llseek.
	 */
	seek_ret = lseek64(fd, off, 0);
	if (seek_ret < 0) {
		return -1;
	}

	ret = read(fd, buf, blk_size * count);
	if (ret < 0) {
		return -1;
	}
	rdcount++;

	return ret;
}

/*
 * Pseduo device writing routine.
 * Write @buf into the device file / a file.
 */
static int device_write(int fd, uint64_t block, int count, int blk_size,
			void *buf)
{
	int ret;
	uint64_t off, seek_ret;

	off = block * blk_size;
	/*
	 * lseek64 is a wrap-up libcall of llseek.
	 */
	seek_ret = lseek64(fd, off, 0);
	if (seek_ret < 0) {
		return -1;
	}

	ret = write(fd, buf, blk_size * count);
	if (ret < 0) {
		return -1;
	}
	return ret;
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

static void *buffer_writeback(void *arg);

struct block_device *bdev_alloc(int fd, int blocksize_bits)
{
	struct block_device *bdev;
	struct super_block *super;

	bdev = malloc(sizeof(struct block_device) + sizeof(struct super_block));
	memset(bdev, 0,
	       sizeof(struct block_device) + sizeof(struct super_block));
	super = (struct super_block *)(bdev + 1);

	bdev->bd_fd = fd;
	bdev->bd_flags = 0;
	bdev->bd_super = super;

	INIT_LIST_HEAD(&bdev->bd_bh_free);
	INIT_LIST_HEAD(&bdev->bd_bh_dirty);
	pthread_mutex_init(&bdev->bd_bh_free_lock, NULL);
	pthread_mutex_init(&bdev->bd_bh_dirty_lock, NULL);
	pthread_mutex_init(&bdev->bd_bh_root_lock, NULL);

	super->s_blocksize_bits = blocksize_bits;
	super->s_blocksize = 1 << super->s_blocksize_bits;
	super->s_bdev = bdev;

	pipe(bdev->bd_bh_writeback_wakeup_fd);
	pthread_create(&bdev->bd_bh_writeback_thread, NULL,
			buffer_writeback, bdev);

	return bdev;
}

static void bdev_writeback_thread_notify(struct block_device *bdev)
{
	char test_byte = 1;
	write(bdev->bd_bh_writeback_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static void bdev_writeback_thread_notify_exit(struct block_device *bdev)
{
	char test_byte = -1;
	write(bdev->bd_bh_writeback_wakeup_fd[1], &test_byte, sizeof(test_byte));
}

static char bdev_writeback_thread_read_notify(struct block_device *bdev)
{
	char test_byte = 0;
	read(bdev->bd_bh_writeback_wakeup_fd[0], &test_byte, sizeof(test_byte));
	return test_byte;
}

static int bdev_is_notify_exiting(char byte)
{
	if (byte < 0)
		return 1;
	return 0;
}

static int sync_dirty_buffer(struct buffer_head *bh);
static void detach_bh_from_freelist(struct buffer_head *bh);
static void buffer_free(struct buffer_head *bh);

void bdev_free(struct block_device *bdev)
{
	void *ret;
	struct rb_node *node;

	bdev_writeback_thread_notify_exit(bdev);
	pthread_join(bdev->bd_bh_writeback_thread, NULL);
	
	while (!list_empty(&bdev->bd_bh_dirty)) {
		struct buffer_head *cur;
		cur = list_first_entry(&bdev->bd_bh_dirty,
				       struct buffer_head, b_dirty_list);
		sync_dirty_buffer(cur);
	}

	pthread_mutex_lock(&bdev->bd_bh_root_lock);
	while (node = rb_first(&bdev->bd_bh_root)) {
		struct buffer_head *bh = rb_entry(
		    node, struct buffer_head, b_rb_node);
		detach_bh_from_freelist(bh);
		__buffer_remove(bdev, bh);
		buffer_free(bh);
	}
	pthread_mutex_unlock(&bdev->bd_bh_root_lock);

	if (bdev->bd_nr_free != 0)
		printf("Warning: ""bdev->bd_nr_free == %d\n", bdev->bd_nr_free);

	close(bdev->bd_bh_writeback_wakeup_fd[0]);
	close(bdev->bd_bh_writeback_wakeup_fd[1]);

	pthread_mutex_destroy(&bdev->bd_bh_free_lock);
	pthread_mutex_destroy(&bdev->bd_bh_dirty_lock);
	pthread_mutex_destroy(&bdev->bd_bh_root_lock);

	free(bdev);
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
	bh = malloc(sizeof(struct buffer_head) + page_size);
	if (!bh)
		return NULL;

	memset(bh, 0, sizeof(struct buffer_head));
	bh->b_bdev = bdev;
	bh->b_data = (char *)(bh + 1);
	bh->b_size = page_size;
	bh->b_blocknr = block;
	bh->b_count = 0;
	bh->b_page = NULL;

	pthread_mutex_init(&bh->b_lock, NULL);
	INIT_LIST_HEAD(&bh->b_freelist);
	INIT_LIST_HEAD(&bh->b_dirty_list);

	sync_writeback_buffers(bdev);

	return bh;
}

static void buffer_free(struct buffer_head *bh)
{
	struct block_device *bdev;
	bdev = bh->b_bdev;

	pthread_mutex_destroy(&bh->b_lock);

	if (bh->b_count != 0) {
		printf("Warning: bh: %p b_count != 0, my pid: %d\n", bh, getpid());
		pthread_kill(pthread_self(), SIGSTOP);
	}

	free(bh);
}

static void
attach_bh_to_freelist(struct buffer_head *bh)
{
	struct block_device *bdev = bh->b_bdev;
	if (list_empty(&bh->b_freelist)) {
		pthread_mutex_lock(&bdev->bd_bh_free_lock);
		list_add(&bh->b_freelist, &bh->b_bdev->bd_bh_free);
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
		list_add(&bh->b_dirty_list, &bh->b_bdev->bd_bh_dirty);
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

/*
 * Submit an IO request.
 * FIXME: any calls to submit_bh are supposed to be non-blocking.
 */
int submit_bh(int is_write, struct buffer_head *bh)
{
	int ret;
	struct block_device *bdev = bh->b_bdev;

	if (is_write == 0) {
		/*memcpy(bh->b_data, bh->b_page, bh->b_size);*/
		ret = device_read(bdev->bd_fd, bh->b_blocknr, 1,
				   bh->b_size, bh->b_data);
		if (ret < 0)
			bh->b_end_io(bh, 0);
		bh->b_end_io(bh, 1);
	} else {
		if (bh->b_page) {
			memcpy(bh->b_page, bh->b_data, bh->b_size);
		} else {
			ret = device_write(bdev->bd_fd, bh->b_blocknr, 1,
					   bh->b_size, bh->b_data);
			if (ret < 0)
				bh->b_end_io(bh, 0);
		}
		bh->b_end_io(bh, 1);
	}

	return 0;
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

void after_submit_read(struct buffer_head *bh, int uptodate)
{
	if (uptodate)
		set_buffer_uptodate(bh);

	put_bh(bh);
	unlock_buffer(bh);
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

/*
 * Release the buffer_head.
 */
void brelse(struct buffer_head *bh)
{
	int refcount;
	if (bh == NULL)
		return;
	refcount = bh->b_count;
	if (bh->b_count > 1)
		goto out;
	assert(bh->b_count == 1);

	if (!buffer_dirty(bh))
		reclaim_buffer(bh);
	else
		move_buffer_to_writeback(bh);
out:
	put_bh(bh);

	return;
}

static int sync_dirty_buffer(struct buffer_head *bh)
{
	int ret = 0;

	if (!trylock_buffer(bh))
		return ret;

	assert(bh->b_count >= 0);
	if (bh->b_count < 1 && buffer_dirty(bh)) {
		get_bh(bh);
		bh->b_end_io = after_buffer_sync;
		ret = submit_bh(WRITE, bh);
	} else {
		unlock_buffer(bh);
	}
	return ret;
}

static void try_to_sync_buffers(struct block_device *bdev)
{
	int i, diff;
	if (buffer_dirty_count > buffer_dirty_threshold) {
		diff = buffer_dirty_count - buffer_dirty_threshold;
		for (i = 0;i < diff;i++) {
			struct buffer_head *cur;
			cur = remove_first_buffer_from_writeback(bdev);
			if (cur)
				sync_dirty_buffer(cur);

		}
	}
}

static void *buffer_writeback(void *arg)
{
	struct epoll_event epev;
	struct block_device *bdev = arg;
	int epfd = epoll_create(0);
	if (epfd < 0)
		return NULL;
	epoll_ctl(epfd, EPOLL_CTL_ADD, bdev->bd_bh_writeback_wakeup_fd[0], &epev);
	while (1) {
		int ret;
		ret = epoll_wait(epfd, &epev, 1, buffer_writeback_ms);
		if (ret > 0) {
			/* We got an nofication. */
			char command;
			command = bdev_writeback_thread_read_notify(bdev);
			if (bdev_is_notify_exiting(command))
				break;
			else
				ret = 0;

		}
		if (ret == 0) {
			/* just flush out the dirty data. */
			try_to_sync_buffers(bdev);
		}
		if (ret < 0)
			break;

	}
	close(epfd);
	return NULL;
}

uint64_t simple_balloc(struct super_block *device, unsigned long blockcnt)
{
	struct stat64 buf;
	if(fstat64(device->s_bdev->bd_fd, &buf)) {
		perror("fstat64");
		printf("file size: %llu\n", buf.st_size);
		return 0;
	}
	if (posix_fallocate(device->s_bdev->bd_fd, buf.st_size, (uint64_t)blockcnt * device->s_blocksize)) {
		perror("fallocate64");
		printf("file size: %llu, request blockcnt: %lu\n", buf.st_size, blockcnt);
		return 0;
	}

	return buf.st_size / device->s_blocksize;
}

uint64_t device_size(struct block_device *bdev)
{
	struct stat64 buf;
	if(fstat64(bdev->bd_fd, &buf)) {
		perror("fstat64");
		printf("file size: %llu\n", buf.st_size);
		return 0;
	}

	return buf.st_size;
}
