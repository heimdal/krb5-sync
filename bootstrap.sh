#!/bin/sh
if [ "x$1" = "xam" ] ; then
    set -ex
    automake -a -c
    ./config.status
else 
    set -ex

    make maintainer-clean || true

    rm -rf autom4te.cache
    rm -f config.cache

    aclocal
    libtoolize -c --force
    autoheader
    automake -a -c
    autoconf -Wall

    ./configure "$@"
fi

