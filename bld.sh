#!/bin/sh

if gcc -g -o testdiag -O0 -rdynamic -Wall testdiag.c diag.c; then
   :
else
   exit 1
fi

if $HOME/inst/24-64/bin/apxs -ci mod_backtrace.c diag.c; then
    if $HOME/inst/22-64/bin/apxs -ci mod_backtrace.c diag.c; then
	:
    else
	exit 1
    fi
else
    exit 1
fi

if $HOME/inst/24-64/bin/apxs -ci mod_whatkilledus.c; then
    if $HOME/inst/22-64/bin/apxs -ci mod_whatkilledus.c; then
	:
    else
	exit 1
    fi
else
    exit 1
fi
