dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University.
dnl See LICENSE for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.61])
AC_INIT([krb5-sync], [1.2], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.10 -Wall -Werror])
AM_MAINTAINER_MODE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_DISABLE_STATIC
AC_PROG_LIBTOOL
RRA_LIB_KRB5
RRA_LIB_KRB5_SET
RRA_LIB_AFS
AS_IF([test x"$rra_afs" = xtrue],
    [RRA_LIB_KRB4
     RRA_LIB_KRB4_SET
     RRA_LIB_AFS_SET
     AC_CHECK_FUNCS([afs_error_message])])
AM_CONDITIONAL([AFS], [test x"$rra_afs" = xtrue])
AC_SEARCH_LIBS([ldap_initialize], [ldap])

# Crank up the warnings if we're using GCC.
if test "x$GCC" = "xyes" ; then
   CFLAGS="-Wall $CFLAGS"
fi

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
