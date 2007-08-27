dnl Process this file with autoconf to produce a configure script.
dnl $Id$
dnl
dnl Copyright 2006 Board of Trustees, Leland Stanford Jr. University.
dnl See README for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.60])
AC_INIT([krb5-sync], [1.1], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([tools])
AM_INIT_AUTOMAKE([1.10 -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_DISABLE_STATIC
AC_PROG_LIBTOOL
RRA_LIB_KRB5([krb4], [true])
AC_SEARCH_LIBS([ldap_initialize], [ldap])

# Crank up the warnings if we're using GCC.
if test "x$GCC" = "xyes" ; then
   CFLAGS="-Wall $CFLAGS"
fi

AC_ARG_WITH(afsdir, AC_HELP_STRING([--with-afsdir=DIR],
                                      [Directory holding AFS includes/libs]),
                sg_cv_with_afsdir=$withval)
 AC_CACHE_CHECK([for location of AFS directory],
                         sg_cv_with_afsdir, sg_cv_with_afsdir=/usr)

if test x"$sg_cv_with_afsdir" != x/usr ; then
    CFLAGS="-I${sg_cv_with_afsdir}/include $CFLAGS"
fi
LDFLAGS="-L${sg_cv_with_afsdir}/lib -L${sg_cv_with_afsdir}/lib/afs $LDFLAGS"

dnl Once we specify a directory, we try to link a test program.  If the link
dnl works, we store the value of the directory in a cache variable.  If not,
dnl we put _FAILED_ in the cache value.  In this way we don't try to link
dnl the test program if our afsdir value was cached, as we know it works.
AC_MSG_CHECKING([whether the specified AFS dir looks valid])
if test "x${sg_cv_afsdir_link_works:-set}" != "x$sg_cv_with_afsdir"; then
        save_LIBS="$LIBS"
        LIBS="$save_LIBS -lcmd -lafsutil"
        AC_TRY_LINK([#include <afs/param.h>
	             #include <afs/cmd.h>],
                [cmd_CreateAlias((struct cmd_syndesc *)0, "foo")],
                sg_cv_afsdir_link_works=$sg_cv_with_afsdir,
                sg_cv_afsdir_link_works=_FAILED_)
        LIBS="$save_LIBS"
        wasCached=""
else
        wasCached="(cached)"
fi
if test "x$sg_cv_afsdir_link_works" = "x$sg_cv_with_afsdir"; then
        AC_MSG_RESULT([${wasCached} yes])
else
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([Unable to link test program....bad AFS dir specified?])
fi

dnl Much easier to use in XXX.in files
AFSWS=$sg_cv_with_afsdir
AC_SUBST(AFSWS)

dnl And it always needs these libs added
LIBS="$LIBS -lafsauthent -lafsrpc -lpthread"

LIBS="$LIBS -ldl"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
