CC=cc
CC_OPT_FLAGS=-O0 -g3
PKG_LIBS=libsoup-2.4 glib-2.0 gthread-2.0
CFLAGS_RAW=$(shell pkg-config --cflags $(PKG_LIBS))
COMPILER=$(CC) --std=c99 $(CC_OPT_FLAGS) $(CFLAGS)

ifdef DEBUG
	CFLAGS=-DDEBUG=1 $(CFLAGS_RAW)
else
	CFLAGS=$(CFLAGS_RAW)
endif


RESOURCES=res/favicon.ico


.PHONY: all
all: camarero


src/camarero-mime-types.o: src/camarero-mime-types.c src/camarero-mime-types.h
	$(COMPILER) -Isrc -c -o $@ $<


src/camarero.o: src/camarero.c src/config.h
	$(COMPILER) -Isrc -c -o $@ $<


gen/camarero.o:  gen/camarero.c  gen/camarero.h
	$(COMPILER) -Isrc -c -o $@ $<


gen/camarero.c: res/camarero.gresource.xml $(RESOURCES)
	-[ -d gen ] || mkdir gen
	glib-compile-resources --target=$@ --generate-source --c-name camarero $<


gen/camarero.h: res/camarero.gresource.xml $(RESOURCES)
	- [ -d gen ] || mkdir gen
	glib-compile-resources --target=$@ --generate-header --c-name camarero $<


camarero: src/camarero.o src/camarero-mime-types.o gen/camarero.o
	$(CC) `pkg-config --libs $(PKG_LIBS)` -o $@ $^


.PHONY: gdb
gdb: camarero
	G_DEBUG=fatal_warnings gdb ./$<



ifneq ($(shell uname),Darwin)
camarero-static: src/camarero.o src/camarero-mime-types.o
	$(CC) -static -static-libgcc -o $@ $^ `pkg-config --static --libs $(PKG_LIBS)` -lpcre -lselinux
endif


.PHONY: clean
clean:
	rm -f camarero camarero-static src/*.o
	rm -rf gen/
