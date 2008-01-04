dnl afs.m4 -- Find the compiler and linker flags for OpenAFS.
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
dnl Also provides RRA_LIB_AFS_SET to set CPPFLAGS, LDFLAGS, and LIBS to
dnl include the AFS libraries; RRA_LIB_AFS_SWITCH to do the same but save the
dnl current values first; and RRA_LIB_AFS_RESTORE to restore those settings to
dnl before the last RRA_LIB_AFS_SWITCH.
dnl
dnl Written by Russ Allbery <rra@stanford.edu>
dnl Based on code developed by Derrick Brashear and Ken Hornstein of Sine
dnl Nomine Associates, on behalf of Stanford University.
dnl Copyright 2006, 2007, 2008
dnl     Board of Trustees, Leland Stanford Jr. University
dnl See LICENSE for licensing terms.

dnl Set CPPFLAGS, LDFLAGS, and LIBS to values including the AFS settings.
AC_DEFUN([RRA_LIB_AFS_SET],
[CPPFLAGS="$AFS_CPPFLAGS $CPPFLAGS"
 LDFLAGS="$AFS_LDFLAGS $LDFLAGS"
 LIBS="$AFS_LIBS $LIBS"])

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the AFS flags.  Used as a wrapper, with
dnl RRA_LIB_AFS_RESTORE, around tests.
AC_DEFUN([RRA_LIB_AFS_SWITCH],
[rra_afs_save_CPPFLAGS="$CPPFLAGS"
 rra_afs_save_LDFLAGS="$LDFLAGS"
 rra_afs_save_LIBS="$LIBS"
 RRA_LIB_AFS_SET])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_AFS_SWITCH was called).
AC_DEFUN([RRA_LIB_AFS_RESTORE],
[CPPFLAGS="$rra_afs_save_CPPFLAGS"
 LDFLAGS="$rra_afs_save_LDFLAGS"
 LIBS="$rra_afs_save_LIBS"])

dnl The function that does the work checking for the AFS libraries.
AC_DEFUN([_RRA_LIB_AFS_CHECK],
[RRA_LIB_AFS_SET
 LIBS=
 AC_SEARCH_LIBS([pthread_getspecific], [pthread])
 AC_SEARCH_LIBS([res_search], [resolv], ,
    [AC_SEARCH_LIBS([__res_search], [resolv])])
 AC_SEARCH_LIBS([gethostbyname], [nsl])
 AC_SEARCH_LIBS([socket], [socket], ,
    [AC_CHECK_LIB([nsl], [socket], [LIBS="-lnsl -lsocket $LIBS"], ,
        [-lsocket])])
 AFS_LIBS="$AFS_LIBS $LIBS"
 LIBS="$AFS_LIBS"
 AC_CACHE_CHECK([whether linking with AFS libraries work], [rra_cv_lib_afs],
 [AC_TRY_LINK(
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
 RRA_LIB_AFS_RESTORE])

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
