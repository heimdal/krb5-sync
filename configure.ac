dnl Autoconf configuration for krb5-sync.
dnl
dnl Written by Russ Allbery <eagle@eyrie.org>
dnl Copyright 2015 Russ Allbery <eagle@eyrie.org>
dnl Copyright 2006, 2007, 2010, 2012, 2013
dnl     The Board of Trustees of the Leland Stanford Junior University
dnl
dnl See LICENSE for licensing terms.

AC_PREREQ([2.64])
AC_INIT([krb5-sync], [3.1], [eagle@eyrie.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 check-news dist-xz foreign silent-rules subdir-objects
    -Wall -Werror])
AM_MAINTAINER_MODE

dnl Detect unexpanded macros.
m4_pattern_forbid([^_?RRA_])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_INSTALL
AM_DISABLE_STATIC
LT_INIT

dnl Only check for krb5/kadm5_hook_plugin.h if building with MIT, since we may
dnl find a system MIT header file that can't be included when building with
dnl Heimdal.  We use the probe for the krb5_realm data type as a proxy for
dnl whether we're building with Heimdal.
RRA_LIB_KRB5
RRA_LIB_KRB5_SWITCH
AC_CHECK_HEADERS([kadm5/kadm5_err.h])
AC_CHECK_FUNCS([krb5_free_default_realm \
    krb5_free_string \
    krb5_get_init_creds_opt_alloc \
    krb5_get_init_creds_opt_set_default_flags \
    krb5_principal_get_comp_string \
    krb5_principal_get_num_comp \
    krb5_principal_get_realm \
    krb5_principal_set_realm \
    krb5_xfree])
AC_CHECK_TYPES([krb5_realm], [],
    [AC_CHECK_HEADERS([krb5/kadm5_hook_plugin.h])], [RRA_INCLUDES_KRB5])
AC_CHECK_FUNCS([krb5_get_init_creds_opt_free],
    [RRA_FUNC_KRB5_GET_INIT_CREDS_OPT_FREE_ARGS])
AC_CHECK_FUNCS([krb5_appdefault_string], [],
    [AC_CHECK_FUNCS([krb5_get_profile])
     AC_CHECK_HEADERS([k5profile.h profile.h])
     AC_LIBOBJ([krb5-profile])])
RRA_LIB_KRB5_RESTORE

RRA_LIB_KADM5SRV
RRA_LIB_KADM5SRV_SWITCH
AC_CHECK_FUNCS([kadm5_init_krb5_context kadm5_init_with_skey_ctx])
RRA_LIB_KADM5SRV_RESTORE

RRA_LIB_LDAP

dnl Only used for the test suite.
save_LIBS="$LIBS"
AC_SEARCH_LIBS([dlopen], [dl], [DL_LIBS="$LIBS"])
LIBS="$save_LIBS"
AC_SUBST([DL_LIBS])

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([sys/bittypes.h sys/select.h sys/time.h syslog.h])
AC_CHECK_DECLS([snprintf, vsnprintf])
RRA_C_C99_VAMACROS
RRA_C_GNU_VAMACROS
AC_TYPE_LONG_LONG_INT
AC_TYPE_UINT32_T
AC_CHECK_TYPES([ssize_t], [], [],
    [#include <sys/types.h>])
RRA_FUNC_SNPRINTF
AC_CHECK_FUNCS([setrlimit])
AC_REPLACE_FUNCS([asprintf mkstemp reallocarray strndup])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
