CC=gcc -O0 -g3 --std=c99
PKG_LIBS=libsoup-2.4
CFLAGS_RAW = $(shell pkg-config --cflags $(PKG_LIBS))
LIBS = $(shell pkg-config --libs $(PKG_LIBS))
COMPILER=$(CC) $(CFLAGS)
LINKER=$(CC) $(LIBS)

ifdef DEBUG
	CFLAGS=-DDEBUG=1 $(CFLAGS_RAW)
else
	CFLAGS=$(CFLAGS_RAW)
endif


.PHONEY: all
all: camarero


src/camarero-mime-types.o: src/camarero-mime-types.c src/camarero-mime-types.h
	$(COMPILER) -Isrc -c -o $@ $<


src/camarero.o: src/camarero.c src/config.h
	$(COMPILER) -Isrc -c -o $@ $<


camarero: src/camarero.o src/camarero-mime-types.o
	$(LINKER) -o $@ $^


.PHONEY: clean
clean:
	rm -f src/*.o
	rm -f camarero
