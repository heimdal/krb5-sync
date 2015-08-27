/*
 * Store errors in the Kerberos context.
 *
 * Provides helper functions for the rest of the plugin code to store an error
 * message in the Kerberos context.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2015 Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <ldap.h>

#include <plugin/internal.h>


/*
 * Internal helper function to set the Kerberos error message given a format,
 * an error code, and a variable argument structure.  Returns the error code
 * set, which is normally the same as the one passed in, but which may change
 * if we can't allocate memory.
 */
static krb5_error_code __attribute__((__format__(printf, 3, 0)))
set_error(krb5_context ctx, krb5_error_code code, const char *format,
          va_list args)
{
    char *message;

    if (vasprintf(&message, format, args) < 0)
        return sync_error_system(ctx, "cannot allocate memory");
    krb5_set_error_message(ctx, code, "%s", message);
    free(message);
    return code;
}


/*
 * Set the Kerberos error code to indicate a server configuration error and
 * set the message to the format and arguments passed to this function.
 */
krb5_error_code
sync_error_config(krb5_context ctx, const char *format, ...)
{
    va_list args;
    krb5_error_code code;

    va_start(args, format);
    code = set_error(ctx, KADM5_MISSING_KRB5_CONF_PARAMS, format, args);
    va_end(args);
    return code;
}


/*
 * Set the Kerberos error code to a generic kadmin failure error and the
 * message to the format and arguments passed to this function.  This is used
 * for internal failures of various types.
 */
krb5_error_code
sync_error_generic(krb5_context ctx, const char *format, ...)
{
    va_list args;
    krb5_error_code code;

    va_start(args, format);
    code = set_error(ctx, KADM5_FAILURE, format, args);
    va_end(args);
    return code;
}


/*
 * Set the Kerberos error code to a generic service unavailable error and the
 * message to the format and arguments passed to this function with the LDAP
 * error string appended.
 */
krb5_error_code
sync_error_ldap(krb5_context ctx, int code, const char *format, ...)
{
    va_list args;
    char *message;
    bool okay = true;
    int oerrno;

    va_start(args, format);
    if (vasprintf(&message, format, args) < 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, errno, "cannot allocate memory: %s",
                               strerror(errno));
        okay = false;
    }
    va_end(args);
    if (!okay)
        return oerrno;
    krb5_set_error_message(ctx, KADM5_FAILURE, "%s: %s", message,
                           ldap_err2string(code));
    free(message);
    return KADM5_FAILURE;
}


/*
 * Set the Kerberos error code to the current errno and the message to the
 * format and arguments passed to this function.
 */
krb5_error_code
sync_error_system(krb5_context ctx, const char *format, ...)
{
    va_list args;
    char *message;
    bool okay = true;
    int oerrno = errno;

    va_start(args, format);
    if (vasprintf(&message, format, args) < 0) {
        oerrno = errno;
        krb5_set_error_message(ctx, errno, "cannot allocate memory: %s",
                               strerror(errno));
        okay = false;
    }
    va_end(args);
    if (!okay)
        return oerrno;
    krb5_set_error_message(ctx, oerrno, "%s: %s", message, strerror(oerrno));
    free(message);
    return oerrno;
}
