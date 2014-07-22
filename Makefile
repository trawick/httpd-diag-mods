# Copyright 2012, 2014 Jeff Trawick, http://emptyhammock.com/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

BITS := $(shell $(HTTPD)/bin/apachectl -V | grep Architecture | sed -e 's/^Architecture: *//' -e 's/-bit.*//')

DEFBITS := -DDIAG_BITS_$(BITS)

BASE_CFLAGS=$(DEFBITS)

PLATFORM := $(shell uname -s)
MACHINE  := $(shell uname -m)

$(info Building for platform $(PLATFORM))

GCC_CFLAGS=-O0 -Wall -m$(BITS)
CLANG_CFLAGS=$(GCC_CFLAGS)

ifeq ($(PLATFORM), FreeBSD)

ifeq ($(CLANG), yes)

CC=cc
CFLAGS = $(BASE_CFLAGS) $(CLANG_CFLAGS) -rdynamic
LDFLAGS = $(CLANG_CFLAGS) -rdynamic

else

CC=gcc
CFLAGS = $(BASE_CFLAGS) $(GCC_CFLAGS) -rdynamic
LDFLAGS = $(GCC_CFLAGS) -rdynamic

endif

CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
LIBS=-lexecinfo

else

ifeq ($(PLATFORM), Linux)

CC=gcc
CFLAGS=  $(BASE_CFLAGS) $(GCC_CFLAGS) -rdynamic
LDFLAGS= $(GCC_CFLAGS) -rdynamic
LIBS=

ifeq ($(MACHINE), armv6l)
CFLAGS += -funwind-tables
endif

else

ifeq ($(PLATFORM), SunOS)

CC=cc
CFLAGS=$(BASE_CFLAGS) -DSOLARIS
LDFLAGS=
LIBS=

else

CC=gcc
CFLAGS=$(BASE_CFLAGS) $(GCC_CFLAGS)
LDFLAGS=$(GCC_CFLAGS)
LIBS=

endif

endif

endif

ifeq ($(LIBUNWIND),yes)
CFLAGS += -DDIAG_HAVE_LIBUNWIND_BACKTRACE=1

ifneq ($(PLATFORM), Darwin)
LIBS = -lunwind
endif

ifeq ($(PLATFORM), Linux)
LIBS += -ldl
endif

endif

TARGETS = testdiag testcrash mod_backtrace.la mod_whatkilledus.la mod_crash.la

all: $(TARGETS)

install: $(TARGETS)
	$(HTTPD)/bin/apxs -i mod_backtrace.la
	$(HTTPD)/bin/apxs -i mod_whatkilledus.la

install-mod-crash: mod_crash.la
	$(HTTPD)/bin/apxs -i mod_crash.la

mod_backtrace.la: mod_backtrace.c mod_backtrace.h diag.h diag.c
	$(HTTPD)/bin/apxs -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_backtrace.c diag.c $(LIBS)

mod_crash.la: mod_crash.c
	$(HTTPD)/bin/apxs -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_crash.c $(LIBS)

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
