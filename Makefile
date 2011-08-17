CC=gcc -O0 -g3 --std=c99
PKG_LIBS=libsoup-2.4
CFLAGS = $(shell pkg-config --cflags $(PKG_LIBS))
LIBS = $(shell pkg-config --libs $(PKG_LIBS))
COMPILER=$(CC) $(CFLAGS) $(LIBS)


.PHONEY: all
all: camarero


camarero: src/camarero.c src/config.h
	$(COMPILER) -Isrc -o $@ $<


.PHONEY: clean
clean:
	rm -f camarero
