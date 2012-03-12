CC=cc
CC_OPT_FLAGS=-O0 -g3
PKG_LIBS=libsoup-2.4 glib-2.0 gthread-2.0
CFLAGS_RAW=$(shell pkg-config --cflags $(PKG_LIBS))
LIBS=$(shell pkg-config --libs $(PKG_LIBS))
COMPILER=$(CC) --std=c99 $(CC_OPT_FLAGS) $(CFLAGS)
LINKER=$(CC) $(LIBS)

ifdef DEBUG
	CFLAGS=-DDEBUG=1 $(CFLAGS_RAW)
else
	CFLAGS=$(CFLAGS_RAW)
endif


.PHONY: all
all: camarero


src/camarero-mime-types.o: src/camarero-mime-types.c src/camarero-mime-types.h
	$(COMPILER) -Isrc -c -o $@ $<


src/camarero.o: src/camarero.c src/config.h
	$(COMPILER) -Isrc -c -o $@ $<


camarero: src/camarero.o src/camarero-mime-types.o
	$(LINKER) -o $@ $^


.PHONY: gdb
gdb: camarero
	G_DEBUG=fatal_warnings gdb ./$<



ifneq ($(shell uname),Darwin)
camarero-static: src/camarero.o src/camarero-mime-types.o
	$(LINKER) -static -static-libgcc -o $@ $^ `pkg-config --static --libs $(PKG_LIBS)` -lpcre -lselinux
endif


.PHONY: clean
clean:
	rm -f camarero camarero-static src/*.o
