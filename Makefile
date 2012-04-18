CC=cc
CC_OPT_FLAGS=-O0 -g3
PKG_LIBS=libsoup-2.4 glib-2.0 gthread-2.0
CFLAGS_RAW=$(shell pkg-config --cflags $(PKG_LIBS))
ifdef DEBUG
	CFLAGS=-DDEBUG=1 $(CFLAGS_RAW)
else
	CFLAGS=$(CFLAGS_RAW)
endif
COMPILER=$(CC) --std=c99 $(CC_OPT_FLAGS) $(CFLAGS) -Igen


RESOURCES=res/favicon.ico res/index.html


.PHONY: all
all: camarero


gen/camarero-resources.c: res/camarero.gresource.xml $(RESOURCES)
	@-[ -d gen ] || mkdir gen
	glib-compile-resources --target=$@ --generate-source --c-name camarero $<

gen/camarero-resources.h: res/camarero.gresource.xml $(RESOURCES)
	@-[ -d gen ] || mkdir gen
	glib-compile-resources --target=$@ --generate-header --c-name camarero $<

gen/camarero-mime-types.o: src/camarero-mime-types.c src/camarero-mime-types.h
	@-[ -d gen ] || mkdir gen
	$(COMPILER) -Isrc -c -o $@ $<

gen/camarero.o: src/camarero.c src/config.h gen/camarero-resources.h
	@-[ -d gen ] || mkdir gen
	$(COMPILER) -Isrc -c -o $@ $<

gen/camarero-resources.o: gen/camarero-resources.c gen/camarero-resources.h
	@-[ -d gen ] || mkdir gen
	$(COMPILER) -Isrc -c -o $@ $<


.PHONY: camarero
camarero: gen/camarero
gen/camarero: gen/camarero.o gen/camarero-mime-types.o gen/camarero-resources.o
	$(CC) -o $@ $^ `pkg-config --libs $(PKG_LIBS)`


.PHONY: gdb
gdb: gen/camarero
	G_DEBUG=fatal_warnings gdb ./$<


ifneq ($(shell uname),Darwin)
.PHONY: static
static: gen/camarero-static
gen/camarero-static: gen/camarero.o gen/camarero-mime-types.o gen/camarero-resources.o
	$(CC) -static -static-libgcc -o $@ $^ `pkg-config --static --libs $(PKG_LIBS)` -lpcre -lselinux
endif


.PHONY: clean
clean:
	rm -f camarero camarero-static src/*.o
	-[ -d gen ] && rm -rf gen/*
