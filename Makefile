PKGS := apr-1 libcurl
CFLAGS := -g -O2
LDFLAGS := -Wl,--as-needed $(shell pkg-config --libs-only-L $(PKGS))
LIBS := $(shell pkg-config --libs-only-l $(PKGS)) -lev -lpthread
DESTDIR ?=
PREFIX := /usr/local
VERSION := 0.3.2-0
GIT_ROOT := ../

-include config.mk

ccFLAGS := $(CFLAGS) -Ithird_party -DVERSION=\"$(VERSION)\" -std=c99 -D_GNU_SOURCE -Wall -Wno-strict-aliasing $(shell pkg-config --cflags $(PKGS))

LIB_SRC := http_server.c httputil.c sockutil.c third_party/picohttpparser.c http_response.c
LIB := libhsrv.a
SRC := main.c $(LIB_SRC)
OBJ := $(patsubst %.c,%.o,$(SRC))

all: main bench $(LIB)

.PHONY: dep deb clean distclean depclean tag install config autoversion

r: main
	./main

v: main
	valgrind --tool=memcheck --leak-check=full  ./main

s: main
	strace -e writev ./main

g: main
	gdb --args ./main

-include .deps

.SUFFIXES:

$(LIB): $(patsubst %.c,%.o,$(LIB_SRC))
	ar cru $@ $^

main: main.o $(LIB)
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

bench: bench.o $(LIB)
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

%.o: %.c config.mk
	$(CC) -o $@ -c $(ccFLAGS) $<

# also remove packag files
clean:
	rm -f main bench bench.o header.gperf header.gperf.c header.h libhsrv.pc $(LIB) $(OBJ)

distclean: clean
	rm -f header.h header.gperf header.gperf.c config.mk .deps

%.gperf.c: %.gperf
	gperf --output-file=$@ $<

header.h header.gperf: autogen/header.def autogen/header.tpl
	autogen -L autogen $<

dep .deps: | header.gperf.c header.h
	$(CC) -MM $(ccFLAGS) $(SRC) > .deps

tag: dep
	tr -d ':\\' < .deps | tr ' ' '\n' | sort -u | xargs ctags

ycm:
	echo "$(ccFLAGS)" > .clang_complete

# install pkg-config file pointing to local development directory
pclocal:
	sed -re 's:@prefix@:$(CURDIR):g' -e 's:(\$$\{prefix\})(/include|/lib).*:\1:' libhsrv.pc.in > $(D)/libhsrv.pc

D := $(DESTDIR)$(PREFIX)
install: $(LIB)
	umask 022
	mkdir -p $(D)/include/hsrv $(D)/lib/pkgconfig
	sed -e 's:@prefix@:$(PREFIX):g' libhsrv.pc.in > libhsrv.pc
	install -m 0644 http_server.h header.h pstr.h $(D)/include/hsrv
	install -m 0644 $(LIB) $(D)/lib
	install -m 0644 libhsrv.pc $(D)/lib/pkgconfig

config config.mk: | .deps
	# ensure required libraries are present
	@for p in $(PKGS); do \
		echo -n "Using $$p "; \
		pkg-config --modversion $$p; \
	done
	# checking autogen
	@autogen --version
	# generating config
	> config.mk
	echo "PREFIX:=$(PREFIX)" >> config.mk
	echo "CFLAGS:=$(CFLAGS)" >> config.mk
	echo "VERSION:=$(VERSION)" >> config.mk
