/*
 * Error reporting routines.
 *
 * Set the plugin error string based on a provided error message and an
 * optional Kerberos error to append to the end of the string.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2010, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
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
    if (ctx == NULL || code == 0)
        return;
    if (used < 0 || (size_t) used >= length)
        return;
    message = krb5_get_error_message(ctx, code);
    if (message != NULL)
        snprintf(buffer + used, length - used, ": %s", message);
    krb5_free_error_message(ctx, message);
}
