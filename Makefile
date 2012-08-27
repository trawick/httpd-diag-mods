PLATFORM := $(shell uname -s)

$(info Building for platform $(PLATFORM))

ifeq ($(PLATFORM), FreeBSD)

CFLAGS = -I/usr/local/include -rdynamic
LDFLAGS=-L/usr/local/lib -rdynamic
LIBS=-lexecinfo

else

CFLAGS=
LDFLAGS=
LIBS=

endif

all: testdiag

testdiag: testdiag.o diag.o
	gcc $(LDFLAGS) -o testdiag -g testdiag.o diag.o $(LIBS)

testdiag.o: testdiag.c diag.h
	gcc -c $(CFLAGS) -Wall -g testdiag.c

diag.o: diag.c diag.h
	gcc -c $(CFLAGS) -Wall -g diag.c

clean:
	rm -f testdiag *.o
