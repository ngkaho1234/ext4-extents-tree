CC=clang
CFLAG=-g -fPIC -pie -I. -lpthread -lrt -Wall -DUSE_AIO -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE

COMMON_SRC=extents_bh.c buffer.c rbtree.c ext4_crc32.c db_bitmap.c db.c
EXTENTS= $(COMMON_SRC) extents.c

all: extdel extmaker extmaker.rev mkdb extrm

extdel: extdel.c $(EXTENTS)
	$(CC) $(CFLAG) $^ -o $@

extrm: extrm.c $(EXTENTS)
	$(CC) $(CFLAG) $^ -o $@

extmaker: extmaker.c $(EXTENTS)
	$(CC) $(CFLAG) $^ -o $@

extmaker.rev: extmaker.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_REVERSE $^ -o $@

mkdb: mkdb.c $(EXTENTS)
	$(CC) $(CFLAG) $^ -o $@

clean:
	rm -f extmaker extdel extmaker.rev mkdb extrm
