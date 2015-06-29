#include "db.h"
#include "buffer.h"
#include "ext4_bitmap.h"

#include <getopt.h>
#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

struct arg_table {
	char path[MAXPATHLEN];
	unsigned long long size;
};

void usage(int argc, char **argv)
{
	printf("Usage: %s <-f filename> <-n block_count>\n", argv[0]);
}

static int initialize_bitmap(struct db_header *bhdr, struct super_block *sb)
{
	int i;
	uint64_t dev_blockcnt = device_size(sb->s_bdev) >> sb->s_blocksize_bits;
	int blocks_count;
	struct db_bitmap *db_bitmap = load_all_bitmap(sb, dev_blockcnt, bhdr->db_bitmap_block);
	if (!db_bitmap)
		return -EIO;

	blocks_count = blocks_of_bitmap(sb, dev_blockcnt);

	bitmap_bits_set(db_bitmap, 0);
	printf("device block count: %llu, bitmap blocks count: %d\n", dev_blockcnt, blocks_count);
	for(i = 0;i < blocks_count;i++)
		bitmap_bits_set(db_bitmap, bhdr->db_bitmap_block + i);

	save_all_bitmap(sb, db_bitmap);
	free_all_bitmap(db_bitmap);
	return 0;
}

int mkdb(struct arg_table *tbl)
{
	int fd;
	struct block_device *bdev;
	struct buffer_head *bh;
	struct db_header *bhdr;
	printf("Path: %s, size: %llu blocks\n", tbl->path, tbl->size);
	fd = device_open(tbl->path);
	if (fd < 0) {
		perror("mkdb");
		return -1;
	}
	bdev = bdev_alloc(fd, DB_BLOCKSIZE_BITS);
	if (!bdev) {
		close(fd);
		fprintf(stderr, "mkdb: ""Insufficient resoures.\n");
		return -1;
	}
	simple_balloc(bdev->bd_super, (tbl->size));
	bh = sb_getblk(bdev->bd_super, 0);
	if (!bh) {
		close(fd);
		return -1;
	}
	memset(bh->b_data, 0, bh->b_size);
	bhdr = (struct db_header *)bh->b_data;
	bhdr->db_magic = DB_MAGIC;
	bhdr->db_nrblocks = (tbl->size);
	bhdr->db_bitmap_block = 1;
	bhdr->db_nrblocks = device_size(bdev->bd_super->s_bdev) >> bdev->bd_super->s_blocksize_bits;
	set_buffer_dirty(bh);
	brelse(bh);
	printf("Initialize: %s\n", initialize_bitmap(bhdr, bdev->bd_super)?"failed":"done");
	bdev_free(bdev);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	int index = -1;
	int opt;
	struct arg_table argtbl;

	while ((opt = getopt(argc, argv, "n:f:")) != -1) {
		switch (opt) {
		case 'n':
			argtbl.size = atoll(optarg);
			break;
		case 'f':
			/* FIXME: Beware of overflowing!!!. */
			strcpy(argtbl.path, optarg);
			break;
		default:
			usage(argc, argv);
			exit(EXIT_FAILURE);
		}
		index++;
	}
	if (index < 0) {
		usage(argc, argv);
		exit(EXIT_FAILURE);
	}
	if (mkdb(&argtbl))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
