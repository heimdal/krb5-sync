dnl afs.m4 -- Find the compiler and linker flags for Kerberos v5.
dnl $Id$
dnl
dnl If --with-afs is given, finds the compiler and linker flags for building
dnl with OpenAFS libraries; sets AFS_CPPFLAGS, AFS_LDFLAGS, and AFS_LIBS as
dnl appropriate; and defines HAVE_AFS.  Provides the macro RRA_LIB_AFS, which
dnl takes no arguments.
dnl
dnl This function also sets rra_afs to true if AFS was requested, which can be
dnl checked to determine if further checks should be done.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Based on code developed by Derrick Brashear and Ken Hornstein of Sine
dnl Nomine Associates, on behalf of Stanford University.
dnl Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
dnl See LICENSE for licensing terms.

dnl The function that does the work checking for the AFS libraries.
AC_DEFUN([_RRA_LIB_AFS_CHECK],
[rra_afs_save_CPPFLAGS="$CPPFLAGS"
rra_afs_save_LDFLAGS="$LDFLAGS"
rra_afs_save_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $AFS_CPPFLAGS"
LDFLAGS="$LDFLAGS $AFS_LDFLAGS"
AC_SEARCH_LIBS([pthread_getspecific], [pthread],
    [AFS_LIBS="$AFS_LIBS -lpthread"])
AC_SEARCH_LIBS([res_search], [resolv], [AFS_LIBS="$AFS_LIBS -lresolv"],
    [AC_SEARCH_LIBS([__res_search], [resolv],
        [AFS_LIBS="$AFS_LIBS -lresolv"])])
LIBS="$rra_afs_save_LIBS"
AC_CACHE_CHECK([whether linking with AFS libraries work], [rra_cv_lib_afs],
[CPPFLAGS="$AFS_CPPFLAGS $CPPFLAGS"
LDFLAGS="$AFS_LDFLAGS $LDFLAGS"
LIBS="$AFS_LIBS $LIBS"
AC_TRY_LINK(
[#include <afs/param.h>
#include <afs/kautils.h>],
[char cell[256] = "EXAMPLE.COM";
char realm[256];
int local;

ka_CellToRealm(cell, realm, &local);],
[rra_cv_lib_afs=yes],
[rra_cv_lib_afs=no])])
AS_IF([test "$rra_cv_lib_afs" = no],
    [AC_MSG_ERROR([unable to link test AFS program])])
CPPFLAGS="$rra_afs_save_CPPFLAGS"
LDFLAGS="$rra_afs_save_LDFLAGS"
LIBS="$rra_afs_save_LIBS"])

dnl The public entry point.  Sets up the --with option and only does the
dnl library check if AFS linkage was requested.
AC_DEFUN([RRA_LIB_AFS],
[rra_afs=false
AFS_CPPFLAGS=
AFS_LDFLAGS=
AFS_LIBS="-lafsauthent -lafsrpc"
AC_SUBST([AFS_CPPFLAGS])
AC_SUBST([AFS_LDFLAGS])
AC_SUBST([AFS_LIBS])
AC_ARG_WITH([afs],
    [AC_HELP_STRING([--with-afs@<:@=DIR@:>@],
        [Compile with AFS kaserver sync support])],
    [AS_IF([test x"$withval" != xno],
        [rra_afs=true
         AS_IF([test x"$withval" != xyes],
            [AFS_CPPFLAGS="-I${withval}/include"
             AFS_LDFLAGS="-L${withval}/lib"])
         _RRA_LIB_AFS_CHECK
         AC_DEFINE([HAVE_AFS], 1,
             [Define to enable AFS kaserver support.])])])])
