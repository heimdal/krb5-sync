/*
 * Error reporting routines.
 *
 * Compatibility wrappers around the Kerberos error reporting routines that
 * handle the latest MIT Kerberos interfaces, the older Heimdal interface, and
 * calling com_err directly if necessary.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <plugin/internal.h>


/*
 * Given an error buffer, its length, a Kerberos context, a Kerberos error,
 * and a format string, write the resulting error string into the buffer and
 * append the Kerberos error.
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
    message = krb5_get_error_message(ctx, code);
    if (message != NULL)
        snprintf(buffer + used, length - used, ": %s", message);
    krb5_free_error_message(ctx, message);
}
