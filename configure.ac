dnl Process this file with autoconf to produce a configure script.
dnl $Id: configure.ac 2823 2006-12-07 03:58:51Z rra $
dnl
dnl Copyright 2006 Board of Trustees, Leland Stanford Jr. University.
dnl See README for licensing terms.

AC_REVISION([$Revision$])
AC_PREREQ([2.60])
AC_INIT([krb5-sync], [0.4], [rra@stanford.edu])
AC_CONFIG_AUX_DIR([tools])
AM_INIT_AUTOMAKE([1.10 -Wall -Werror ])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AM_DISABLE_STATIC

# Crank up the warnings if we're using GCC.
if test "x$GCC" = "xyes" ; then
   CFLAGS="-Wall $CFLAGS"
fi

AC_ARG_WITH(foreign-realm, [  --with-foreign-realm=EXAMPLE.COM		set realm for password propagation],[if test "x$withval" = "xyes"; then AC_MSG_ERROR('--with-foreign-realm requires a value (the foreign realm name)'); else FOREIGNREALM="$withval"; fi], AC_MSG_ERROR('--with-foreign-realm requires a value (the foreign realm name)'))

AC_SUBST(FOREIGNREALM)

AC_ARG_WITH(afs-realm, [  --with-afs-realm=EXAMPLE.COM		set realm for password propagation],[if test "x$withval" = "xyes"; then AC_MSG_ERROR('--with-afs-realm requires a value (the afs realm name)'); else AFSREALM="$withval"; fi], AC_MSG_ERROR('--with-afs-realm requires a value (the afs realm name)'))

AC_SUBST(AFSREALM)

# Checks for libraries.

AC_ARG_WITH(kerberos5,
       [  --with-kerberos5=DIR    point fetchmail compilation at a Kerberos 5 directory],
[
if test "$with_kerberos5" = "no"
then
	with_kerberos5=yes
fi
# and let the tests below guess
if test "$with_kerberos5" != "no"
then
if krb5-config 2> /dev/null >/dev/null ; then
  krb5_prefix=`krb5-config --prefix krb5`
  AC_MSG_RESULT([krb5-config points to kerberosV under $krb5_prefix])
  if test -f ${krb5_prefix}/include/et/com_err.h && \
   ! test -f ${krb5_prefix}/include/com_err.h  ; then
    CEFLAGS="$CEFLAGS -I${krb5_prefix}/include/et"
  fi
  unset krb5_prefix
  CEFLAGS="$CEFLAGS `krb5-config --cflags krb5`"
  LIBS="$LIBS `krb5-config --libs krb5`"
  AC_DEFINE([KERBEROS_V5], [1], [Define to 1 if Kerberos 5 is not Heimdal])
else
  if test "$with_kerberos5" != "yes" 
  then
      LDEFLAGS="$LDEFLAGS -L${with_kerberos5}/lib"
      searchdirs="$with_kerberos5"
  else
      searchdirs="/usr/kerberos /usr/local/krb5 /usr/athena /usr"
  fi
  with_kerberos5=
  for dir in $searchdirs
  do AC_MSG_CHECKING([for Kerberos V in $dir])
     if test -f "$dir/include/krb5.h"
     then
        ac_krblibs=
        if test -f "$dir/include/roken.h"
        then
           ac_krblibs="-lasn1 -lroken -lcom_err"
           AC_MSG_RESULT([Heimdal found])
          dnl Attempt to detect if we need to -ldb2 to link Heimdal
          dnl we assume we do if it is available
           AC_CHECK_LIB(db2, db_open, ac_krblibs="$ac_krblibs -ldb2", [],
                ${LDEFLAGS})
           AC_CHECK_LIB(des, des_string_to_key, libk5crypto=-ldes,
              AC_CHECK_LIB(ssl, MD5_Init, [],
                AC_MSG_ERROR([DES libraries not found. Try adding --with-ssl to enable OpenSSL support]),
                ${LDEFLAGS} ${ac_krblibs}),
           ${LDEFLAGS} ${ac_krblibs})
           AC_DEFINE([HEIMDAL], [1], [Define to 1 if Kerberos 5 is Heimdal])
	   AC_MSG_ERROR([While it may be possible to link a plugin against Heimdal, this is not tested. Please don't do it.])
        else
          AC_MSG_RESULT([found])
          ac_krblibs="-lcom_err"
           AC_CHECK_LIB(crypto,
             krb5_des_string_to_key,
             libk5crypto=-lcrypto,
                AC_CHECK_LIB(k5crypto,
                   krb5_des_string_to_key,
                   libk5crypto=-lk5crypto,
                      AC_CHECK_LIB(k5crypto,
                         krb5_c_string_to_key,
                         libk5crypto=-lk5crypto,
                      AC_MSG_ERROR([Kerberos 5 DES libraries not found]),
                   ${LDEFLAGS} ${ac_krblibs}),
                   ${LDEFLAGS} ${ac_krblibs}),
                 ${LDEFLAGS} ${ac_krblibs})
        fi
        AC_CHECK_LIB(krb5, krb5_init_context,[],
           continue,
           ${LDEFLAGS} ${ac_krblibs})
        AC_CHECK_LIB(krb5, krb5_init_ets,
	   AC_DEFINE([HAVE_KRB5_INIT_ETS], [1], [Define to 1 if Kerberos V library loads its own error tables])
           AC_MSG_RESULT([Kerberos V library loads its own error tables]))
        AC_DEFINE(KERBEROS_V5)
        test "$dir" != "/usr" && CEFLAGS="$CEFLAGS -I$dir/include"
        LDEFLAGS="$LDEFLAGS -L$dir/lib"
       LIBS="$LIBS $ac_krblibs $libk5crypto"
        with_kerberos5=$dir
        break
     else
        AC_MSG_RESULT([not found])
     fi
  done
  if test -z "$with_kerberos5" ; then
     AC_MSG_ERROR([Kerberos 5 libraries not found])
  fi
fi
fi
]) dnl --with-kerberos5=DIR

AC_ARG_WITH(afsdir, AC_HELP_STRING([--with-afsdir=DIR],
                                      [Directory holding AFS includes/libs]),
                sg_cv_with_afsdir=$withval)
 AC_CACHE_CHECK([for location of AFS directory],
                         sg_cv_with_afsdir, sg_cv_with_afsdir=/usr/afsws)

CFLAGS="-I${sg_cv_with_afsdir}/include $CFLAGS"
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

dnl Linking against AFS always needs these
AC_CHECK_LIB(socket, getservbyname)
AC_CHECK_LIB(nsl, gethostbyname)

dnl And it always needs these libs added
LIBS="$LIBS -lafsauthent -lafsrpc -lpthread"

LIBS="$LIBS -ldl"

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([config.h])
AC_OUTPUT
