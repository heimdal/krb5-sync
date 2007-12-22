/* $Id$
 *
 * Error reporting routines.
 *
 * Compatibility wrappers around the Kerberos error reporting routines that
 * handle the latest MIT Kerberos interfaces, the older Heimdal interface, and
 * calling com_err directly if necessary.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
 * See LICENSE for licensing terms.
 */

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#include <krb5.h>
#if !defined(HAVE_KRB5_GET_ERROR_MESSAGE) && !defined(HAVE_KRB5_GET_ERR_TEXT)
# ifdef HAVE_ET_COM_ERR_H
#  include <et/com_err.h>
# else
#  include <com_err.h>
# endif
#endif

#include <plugin/internal.h>

/*
 * Given a Kerberos error code, return the corresponding error.  Prefer the
 * Kerberos interface if available since it will provide context-specific
 * error information, whereas the error_message() call will only provide a
 * fixed message.
 */
static const char *
get_error(krb5_context ctx, krb5_error_code code)
{
    const char *msg;

# if defined(HAVE_KRB5_GET_ERROR_MESSAGE)
    msg = krb5_get_error_message(ctx, code);
# elif defined(HAVE_KRB5_GET_ERR_TEXT)
    msg = krb5_get_err_text(ctx, code);
# else
    msg = error_message(code);
# endif
    if (msg == NULL)
        return "unknown error";
    else
        return msg;
}

/*
 * Free an error string if necessary.  krb5_free_error_message() is thankfully
 * safe to call on static strings; it only frees the pointer if it was a
 * pointer returned by krb5_get_error_message().
 */
static void
free_error(krb5_context ctx, const char *msg)
{
# ifdef HAVE_KRB5_FREE_ERROR_MESSAGE
    krb5_free_error_message(ctx, msg);
# endif
}

/*
 * Given an error buffer, its length, a Kerberos context, a Kerberos error,
 * and a format string, write the resulting error string into the buffer and
 * append the Kerberos error.  This is the public interface called by the rest
 * of the plugin.
 */
void
pwupdate_set_error(char *buffer, size_t length, krb5_context ctx,
                   krb5_error_code code, const char *format, ...)
{
    va_list args;
    ssize_t used;
    const char *message;

    va_start(args, format);
    used = vsnprintf(buffer, length, format, args);
    va_end(args);
    if (used < 0 || (size_t) used >= length)
        return;
    message = get_error(ctx, code);
    if (message != NULL)
        snprintf(buffer + used, length - used, ": %s", message);
    free_error(ctx, message);
}
