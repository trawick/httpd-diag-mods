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

# User can specify APXS or HTTPD.  APXS is preferred, since it will work
# with more layouts.  With HTTPD, we must assume the default layout.

ifeq ($(APXS),)
ifeq ($(HTTPD),)
$(error Either APXS (preferred) or HTTPD must be specified)
else
APXS = $(HTTPD)/bin/apxs
endif
endif

ifeq ($(APACHECTL),)
APACHECTL = $(shell $(APXS) -q sbindir)/apachectl
endif

ifeq ($(BITS),)
BITS := $(shell $(APACHECTL) -V | grep Architecture | sed -e 's/^Architecture: *//' -e 's/-bit.*//')
endif

ifeq ($(BITS),)
$(error $(APACHECTL) -V failed)
endif

# can't do this only if CC is unset because of make's default CC setting
CC = $(shell $(APXS) -q CC)

ifeq ($(CC),)
$(error $(APXS) -q CC failed)
endif

DEFBITS := -DDIAG_BITS_$(BITS)

BASE_CFLAGS=$(DEFBITS)

PLATFORM := $(shell uname -s)
MACHINE  := $(shell uname -m)

$(info Building for platform $(PLATFORM))

GCC_CFLAGS=-O0 -Wall
CLANG_CFLAGS=$(GCC_CFLAGS)

ifeq ($(PLATFORM), FreeBSD)

ifeq ($(CLANG),)
MAYBE_CLANG = $(shell $(CC) --version | grep clang | sed -e 's/^.*clang.*$$/clang/')
ifeq ($(MAYBE_CLANG), clang)
CLANG = yes
endif
endif

ifeq ($(CLANG), yes)

CFLAGS = $(BASE_CFLAGS) $(CLANG_CFLAGS)
LDFLAGS = $(CLANG_CFLAGS) -rdynamic

else

CFLAGS = $(BASE_CFLAGS) $(GCC_CFLAGS) -rdynamic
LDFLAGS = $(GCC_CFLAGS) -rdynamic

endif

ifeq ($(LIBUNWIND), yes)

CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
LIBS=-lunwind

else

CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
LIBS=-lexecinfo

endif

else

ifeq ($(PLATFORM), Linux)

CFLAGS=  $(BASE_CFLAGS) $(GCC_CFLAGS) -rdynamic
LDFLAGS= $(GCC_CFLAGS) -rdynamic
LIBS=

ifeq ($(MACHINE), armv6l)
CFLAGS += -funwind-tables
endif

else

ifeq ($(PLATFORM), SunOS)

CFLAGS=$(BASE_CFLAGS) -DSOLARIS
LDFLAGS=
LIBS=

else

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
	$(APXS) -i mod_backtrace.la
	$(APXS) -i mod_whatkilledus.la

install-mod-crash: mod_crash.la
	$(APXS) -i mod_crash.la

mod_backtrace.la: mod_backtrace.c mod_backtrace.h diag.h diag.c
	$(APXS) -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_backtrace.c diag.c $(LIBS)

mod_crash.la: mod_crash.c
	$(APXS) -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_crash.c $(LIBS)

mod_whatkilledus.la: mod_whatkilledus.c mod_backtrace.h diag.h diag.c
	$(APXS) -Wc,"$(CFLAGS)" -Wl,"$(LDFLAGS)" -c mod_whatkilledus.c $(LIBS)

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
