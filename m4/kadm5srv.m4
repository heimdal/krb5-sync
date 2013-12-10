dnl Find the compiler and linker flags for the kadmin server library.
dnl
dnl Finds the compiler and linker flags for linking with the kadmin server
dnl library.  Provides the --with-kadm-server, --with-kadm-server-include, and
dnl --with-kadm-server-lib configure option to specify a non-standard path to
dnl the library.  Uses krb5-config where available unless reduced dependencies
dnl is requested or --with-kadm-server-include or --with-kadm-server-lib are
dnl given.
dnl
dnl Provides the macros RRA_LIB_KADM5SRV and RRA_LIB_KADM5SRV_OPTIONAL and
dnl sets the substitution variables KADM5SRV_CPPFLAGS, KADM5SRV_LDFLAGS, and
dnl KADM5SRV_LIBS.  Also provides RRA_LIB_KADM5SRV_SWITCH to set CPPFLAGS,
dnl LDFLAGS, and LIBS to include the kadmin client libraries, saving the
dnl ecurrent values, and RRA_LIB_KADM5SRV_RESTORE to restore those settings
dnl to before the last RRA_LIB_KADM5SRV_SWITCH.  Defines HAVE_KADM5SRV and
dnl sets rra_use_KADM5SRV to true if the library is found.
dnl
dnl Depends on the RRA_LIB helper routines.
dnl
dnl The canonical version of this file is maintained in the rra-c-util
dnl package, available at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2005, 2006, 2007, 2008, 2009, 2011, 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl This file is free software; the authors give unlimited permission to copy
dnl and/or distribute it, with or without modifications, as long as this
dnl notice is preserved.

dnl Save the current CPPFLAGS, LDFLAGS, and LIBS settings and switch to
dnl versions that include the kadmin client flags.  Used as a wrapper, with
dnl RRA_LIB_KADM5SRV_RESTORE, around tests.
AC_DEFUN([RRA_LIB_KADM5SRV_SWITCH], [RRA_LIB_HELPER_SWITCH([KADM5SRV])])

dnl Restore CPPFLAGS, LDFLAGS, and LIBS to their previous values (before
dnl RRA_LIB_KADM5SRV_SWITCH was called).
AC_DEFUN([RRA_LIB_KADM5SRV_RESTORE], [RRA_LIB_HELPER_RESTORE([KADM5SRV])])

dnl Set KADM5SRV_CPPFLAGS and KADM5SRV_LDFLAGS based on rra_KADM5SRV_root,
dnl rra_KADM5SRV_libdir, and rra_KADM5SRV_includedir.
AC_DEFUN([_RRA_LIB_KADM5SRV_PATHS], [RRA_LIB_HELPER_PATHS([KADM5SRV])])

dnl Does the appropriate library checks for reduced-dependency kadmin client
dnl linkage.  The single argument, if "true", says to fail if the kadmin
dnl client library could not be found.
AC_DEFUN([_RRA_LIB_KADM5SRV_REDUCED],
[RRA_LIB_KADM5SRV_SWITCH
 AC_CHECK_LIB([kadm5srv], [kadm5_init_with_password],
    [KADM5SRV_LIBS=-lkadm5srv],
    [AS_IF([test x"$1" = xtrue],
        [AC_MSG_ERROR([cannot find usable kadmin server library])])])
 RRA_LIB_KADM5SRV_RESTORE])

dnl Sanity-check the results of krb5-config and be sure we can really link a
dnl GSS-API program.  If not, fall back on the manual check.
AC_DEFUN([_RRA_LIB_KADM5SRV_CHECK],
[RRA_LIB_HELPER_CHECK([$1], [KADM5SRV], [kadm5_init_with_password],
    [kadmin server])])

dnl Determine GSS-API compiler and linker flags from krb5-config.
AC_DEFUN([_RRA_LIB_KADM5SRV_CONFIG],
[RRA_KRB5_CONFIG([${rra_KADM5SRV_root}], [kadm-server], [KADM5SRV],
    [_RRA_LIB_KADM5SRV_CHECK([$1])],
    [_RRA_LIB_KADM5SRV_PATHS
     _RRA_LIB_KADM5SRV_REDUCED([$1])])])

dnl The core of the library checking, shared between RRA_LIB_KADM5SRV and
dnl RRA_LIB_KADM5SRV_OPTIONAL.  The single argument, if "true", says to fail
dnl if the kadmin client library could not be found.
AC_DEFUN([_RRA_LIB_KADM5SRV_INTERNAL],
[AC_REQUIRE([RRA_ENABLE_REDUCED_DEPENDS])
 AS_IF([test x"$rra_reduced_depends" = xtrue],
    [_RRA_LIB_KADM5SRV_PATHS
     _RRA_LIB_KADM5SRV_REDUCED([$1])],
    [AS_IF([test x"$rra_KADM5SRV_includedir" = x \
            && test x"$rra_KADM5SRV_libdir" = x],
        [_RRA_LIB_KADM5SRV_CONFIG([$1])],
        [_RRA_LIB_KADM5SRV_PATHS
         _RRA_LIB_KADM5SRV_REDUCED([$1])])])])

dnl The main macro for packages with mandatory kadmin client support.
AC_DEFUN([RRA_LIB_KADM5SRV],
[RRA_LIB_HELPER_VAR_INIT([KADM5SRV])
 RRA_LIB_HELPER_WITH([kadm-server], [kadmin server], [KADM5SRV])
 _RRA_LIB_KADM5SRV_INTERNAL([true])
 rra_use_KADM5SRV=true
 AC_DEFINE([HAVE_KADM5SRV], 1, [Define to enable kadmin server features.])])

dnl The main macro for packages with optional kadmin client support.
AC_DEFUN([RRA_LIB_KADM5SRV_OPTIONAL],
[RRA_LIB_HELPER_VAR_INIT([KADM5SRV])
 RRA_LIB_HELPER_WITH_OPTIONAL([kadm-server], [kadmin server], [KADM5SRV])
 AS_IF([test x"$rra_use_KADM5SRV" != xfalse],
    [AS_IF([test x"$rra_use_KADM5SRV" = xtrue],
        [_RRA_LIB_KADM5SRV_INTERNAL([true])],
        [_RRA_LIB_KADM5SRV_INTERNAL([false])])])
 AS_IF([test x"$KADM5SRV_LIBS" != x],
    [rra_use_KADM5SRV=true
     AC_DEFINE([HAVE_KADM5SRV], 1,
         [Define to enable kadmin server features.])])])
