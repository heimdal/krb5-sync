/*
 * Portability wrapper around krb5.h.
 *
 * This header includes krb5.h and then adjusts for various portability
 * issues, primarily between MIT Kerberos and Heimdal, so that code can be
 * written to a consistent API.
 *
 * Unfortunately, due to the nature of the differences between MIT Kerberos
 * and Heimdal, it's not possible to write code to either one of the APIs and
 * adjust for the other one.  In general, this header tries to make available
 * the Heimdal API and fix it for MIT Kerberos, but there are places where MIT
 * Kerberos requires a more specific call.  For those cases, it provides the
 * most specific interface.
 *
 * For example, MIT Kerberos has krb5_free_unparsed_name() whereas Heimdal
 * prefers the generic krb5_xfree().  In this case, this header provides
 * krb5_free_unparsed_name() for both APIs since it's the most specific call.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
 */

#ifndef PORTABLE_KRB5_H
#define PORTABLE_KRB5_H 1

/*
 * Allow inclusion of config.h to be skipped, since sometimes we have to use a
 * stripped-down version of config.h with a different name.
 */
#ifndef CONFIG_H_INCLUDED
# include <config.h>
#endif
#include <portable/macros.h>

#if defined(HAVE_KRB5_H)
# include <krb5.h>
#elif defined(HAVE_KERBEROSV5_KRB5_H)
# include <kerberosv5/krb5.h>
#else
# include <krb5/krb5.h>
#endif
#include <stdlib.h>

BEGIN_DECLS

/* Default to a hidden visibility for all portability functions. */
#pragma GCC visibility push(hidden)

/*
 * AIX included Kerberos includes the profile library but not the
 * krb5_appdefault functions, so we provide replacements that we have to
 * prototype.
 */
#ifndef HAVE_KRB5_APPDEFAULT_STRING
void krb5_appdefault_boolean(krb5_context, const char *, const krb5_data *,
                             const char *, int, int *);
void krb5_appdefault_string(krb5_context, const char *, const krb5_data *,
                            const char *, const char *, char **);
#endif

/*
 * MIT-specific.  The Heimdal documentation says to use free(), but that
 * doesn't actually make sense since the memory is allocated inside the
 * Kerberos library.  Use krb5_xfree instead.
 */
#ifndef HAVE_KRB5_FREE_DEFAULT_REALM
# define krb5_free_default_realm(c, r) krb5_xfree(r)
#endif

/*
 * Heimdal: krb5_xfree, MIT: krb5_free_string, older MIT uses free().  Note
 * that we can incorrectly allocate in the library and call free() if
 * krb5_free_string is not available but something we use that API for is
 * available, such as krb5_appdefaults_*, but there isn't anything we can
 * really do about it.
 */
#ifndef HAVE_KRB5_FREE_STRING
# ifdef HAVE_KRB5_XFREE
#  define krb5_free_string(c, s) krb5_xfree(s)
# else
#  define krb5_free_string(c, s) free(s)
# endif
#endif

/* Heimdal: krb5_xfree, MIT: krb5_free_unparsed_name. */
#ifdef HAVE_KRB5_XFREE
# define krb5_free_unparsed_name(c, p) krb5_xfree(p)
#endif

/*
 * krb5_{get,free}_error_message are the preferred APIs for both current MIT
 * and current Heimdal, but there are tons of older APIs we may have to fall
 * back on for earlier versions.
 *
 * This function should be called immediately after the corresponding error
 * without any intervening Kerberos calls.  Otherwise, the correct error
 * message and supporting information may not be returned.
 */
#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
const char *krb5_get_error_message(krb5_context, krb5_error_code);
#endif
#ifndef HAVE_KRB5_FREE_ERROR_MESSAGE
void krb5_free_error_message(krb5_context, const char *);
#endif

/*
 * Both current MIT and current Heimdal prefer _opt_alloc and _opt_free, but
 * older versions of both require allocating your own struct and calling
 * _opt_init.
 */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_ALLOC
krb5_error_code krb5_get_init_creds_opt_alloc(krb5_context,
                                              krb5_get_init_creds_opt **);
#endif
#ifdef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE
# ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_FREE_2_ARGS
#  define krb5_get_init_creds_opt_free(c, o) krb5_get_init_creds_opt_free(o)
# endif
#else
# define krb5_get_init_creds_opt_free(c, o) free(o)
#endif

/* Heimdal-specific. */
#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
# define krb5_get_init_creds_opt_set_default_flags(c, p, r, o) /* empty */
#endif

/*
 * Heimdal provides a nice function that just returns a const char *.  On MIT,
 * there's an accessor macro that returns the krb5_data pointer, which
 * requires more work to get at the underlying char *.
 */
#ifndef HAVE_KRB5_PRINCIPAL_GET_REALM
const char *krb5_principal_get_realm(krb5_context, krb5_const_principal);
#endif

/*
 * Adjust for other MIT versus Heimdal differences for principal data
 * extraction and manipulation.  The krb5_principal_* functions are all
 * Heimdal and the other interfaces are MIT.
 *
 * Some versions of Heimdal don't export krb5_principal_get_num_comp from
 * libkrb5.  In that case, just look in the data structure.
 */
#ifndef HAVE_KRB5_PRINCIPAL_SET_REALM
# define krb5_principal_set_realm(c, p, r) \
    krb5_set_principal_realm((c), (p), (r))
#endif
#ifndef HAVE_KRB5_PRINCIPAL_GET_COMP_STRING
# define krb5_principal_get_comp_string(c, p, n) \
    ((krb5_princ_component((c), (p), (n)))->data)
#endif
#ifndef HAVE_KRB5_PRINCIPAL_GET_NUM_COMP
# if defined(HAVE_KRB5_PRINC_SIZE) || defined(krb5_princ_size)
#  define krb5_principal_get_num_comp(c, p) krb5_princ_size((c), (p))
# else
#  define krb5_principal_get_num_comp(c, p) ((p)->name.name_string.len)
# endif
#endif

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PORTABLE_KRB5_H */
