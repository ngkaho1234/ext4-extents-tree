CC=gcc
CFLAG=-g -fPIC -pie -I. -lpthread -lrt -Wall -DCONFIG_NR_ITEMS=166400

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
