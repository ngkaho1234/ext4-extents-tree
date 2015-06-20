CC=gcc
CFLAG=-g -fPIC -pie -I. -lpthread
#

COMMON_SRC=extents_bh.c buffer.c rbtree.c ext4_crc32.c db_bitmap.c db.c
EXTENTS= $(COMMON_SRC) extents.c

all: extdel extmaker extdel.rev extmaker.rev mkdb

extdel: main.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_PACK_FILE $^ -o $@

extdel.rev: main.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_PACK_FILE -DCONFIG_REVERSE $^ -o $@

extmaker: main.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_EXTMAKER $^ -o $@

extmaker.rev: main.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_EXTMAKER -DCONFIG_REVERSE $^ -o $@

mkdb: mkdb.c $(EXTENTS)
	$(CC) $(CFLAG) -DCONFIG_EXTMAKER -DCONFIG_REVERSE $^ -o $@

clean:
	rm -f extmaker extdel extmaker.rev extdel.rev mkdb
