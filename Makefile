
all: testdiag

testdiag: testdiag.o diag.o
	gcc -o testdiag -g testdiag.o diag.o

testdiag.o: testdiag.c diag.h
	gcc -c -Wall -g testdiag.c

diag.o: diag.c diag.h
	gcc -c -Wall -g diag.c
