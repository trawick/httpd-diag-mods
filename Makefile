BITS := $(shell $(HTTPD)/bin/httpd -V | grep Architecture | sed -e 's/^Architecture: *//' -e 's/-bit.*//')

DEFBITS := -DDIAG_BITS_$(BITS)

BASE_CFLAGS=$(DEFBITS)

PLATFORM := $(shell uname -s)

$(info Building for platform $(PLATFORM))

GCC_CFLAGS=-O0 -Wall

ifeq ($(PLATFORM), FreeBSD)

CC=gcc
CFLAGS = $(BASE_CFLAGS) $(GCC_CFLAGS) -I/usr/local/include -rdynamic
LDFLAGS= $(GCC_CFLAGS) -L/usr/local/lib -rdynamic
LIBS=-lexecinfo

else

ifeq ($(PLATFORM), Linux)

CC=gcc
CFLAGS=  $(BASE_CFLAGS) $(GCC_CFLAGS) -rdynamic
LDFLAGS= $(GCC_CFLAGS) -rdynamic
LIBS=

else

ifeq ($(PLATFORM), SunOS)

CC=cc
CFLAGS=$(BASE_CFLAGS) -DSOLARIS
LDFLAGS=
LIBS=

else

CC=gcc
CFLAGS=$(BASE_CFLAGS) $(GCC_CFLAGS)
LDFLAGS=
LIBS=

endif

endif

endif

TARGETS = testdiag testcrash mod_backtrace.la mod_whatkilledus.la

all: $(TARGETS)

install: $(TARGETS)
	$(HTTPD)/bin/apxs -i mod_backtrace.la
	$(HTTPD)/bin/apxs -i mod_whatkilledus.la

mod_backtrace.la: mod_backtrace.c mod_backtrace.h diag.h diag.c
	$(HTTPD)/bin/apxs -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_backtrace.c diag.c $(LIBS)

mod_whatkilledus.la: mod_whatkilledus.c mod_backtrace.h diag.h diag.c
	$(HTTPD)/bin/apxs -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_whatkilledus.c $(LIBS)

testdiag: testdiag.o diag.o
	$(CC) $(LDFLAGS) -o testdiag -g testdiag.o diag.o $(LIBS)

testcrash: testcrash.o diag.o
	$(CC) $(LDFLAGS) -o testcrash -g testcrash.o diag.o $(LIBS)

testcrash.o: testcrash.c diag.h
	$(CC) -c $(CFLAGS) -g testcrash.c

diag.o: diag.c diag.h
	$(CC) -c $(CFLAGS) -g diag.c

clean:
	rm -f $(TARGETS) *.o
