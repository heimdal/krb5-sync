/*
 * Retrieve configuratin settings from krb5.conf.
 *
 * Provided here are functions to retrieve boolean, numeric, and string
 * settings from krb5.conf.  This wraps the somewhat awkward
 * krb5_appdefaults_* functions.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>

#include <plugin/internal.h>
#include <util/macros.h>

/* The representation of the realm differs between MIT and Kerberos. */
#ifdef HAVE_KRB5_REALM
typedef krb5_realm realm_type;
#else
typedef krb5_data *realm_type;
#endif


/*
 * Obtain the default realm and translate it into the format required by
 * krb5_appdefault_*.  This is obnoxious for MIT Kerberos, which returns the
 * default realm as a string but expects the realm as a krb5_data type when
 * calling krb5_appdefault_*.
 */
#ifdef HAVE_KRB5_REALM

static realm_type
default_realm(krb5_context ctx)
{
    krb5_error_code code;
    realm_type realm;

    code = krb5_get_default_realm(ctx, &realm);
    if (code != 0)
        realm = NULL;
    return realm;
}

#else /* !HAVE_KRB5_REALM */

static realm_type
default_realm(krb5_context ctx)
{
    char *realm = NULL;
    krb5_error_code code;
    krb5_data *realm_data;

    realm_data = calloc(1, sizeof(krb5_data));
    if (realm_data == NULL)
        return NULL;
    code = krb5_get_default_realm(ctx, &realm);
    if (code != 0) {
        free(realm);
        return NULL;
    }
    realm_data->magic = KV5M_DATA;
    realm_data->data = strdup(realm);
    if (realm_data->data == NULL) {
        free(realm_data);
        krb5_free_default_realm(ctx, realm);
        return NULL;
    }
    realm_data->length = strlen(realm);
    krb5_free_default_realm(ctx, realm);
    return realm_data;
}

#endif /* !HAVE_KRB5_REALM */


/*
 * Free the default realm data in whatever form it was generated for the calls
 * to krb5_appdefault_*.
 */
#ifdef HAVE_KRB5_REALM

static void
free_default_realm(krb5_context ctx UNUSED, realm_type realm)
{
    krb5_free_default_realm(ctx, realm);
}

#else /* !HAVE_KRB5_REALM */

static void
free_default_realm(krb5_context ctx UNUSED, realm_type realm)
{
    free(realm->data);
    free(realm);
}

#endif /* !HAVE_KRB5_REALM */


/*
 * Load a boolean option from Kerberos appdefaults.  Takes the Kerberos
 * context, the option, and the result location.
 */
void
sync_config_boolean(krb5_context ctx, const char *opt, bool *result)
{
    realm_type realm;
    int tmp;

    /*
     * The MIT version of krb5_appdefault_boolean takes an int * and the
     * Heimdal version takes a krb5_boolean *, so hope that Heimdal always
     * defines krb5_boolean to int or this will require more portability work.
     */
    realm = default_realm(ctx);
    krb5_appdefault_boolean(ctx, "krb5-sync", realm, opt, *result, &tmp);
    *result = tmp;
    free_default_realm(ctx, realm);
}


/*
 * Load a list option from Kerberos appdefaults.  Takes the Kerberos context,
 * the option, and the result location.  The option is read as a string and
 * the split on spaces and tabs into a list.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value.
 */
krb5_error_code
sync_config_list(krb5_context ctx, const char *opt, struct vector **result)
{
    realm_type realm;
    char *value = NULL;

    /* Obtain the string from [appdefaults]. */
    realm = default_realm(ctx);
    krb5_appdefault_string(ctx, "krb5-sync", realm, opt, "", &value);
    free_default_realm(ctx, realm);

    /* If we got something back, store it in result. */
    if (value != NULL) {
        if (value[0] != '\0') {
            *result = sync_vector_split_multi(value, " \t", *result);
            if (*result == NULL)
                return sync_error_system(ctx, "cannot allocate memory");
        }
        krb5_free_string(ctx, value);
    }
    return 0;
}


/*
 * Load a string option from Kerberos appdefaults.  Takes the Kerberos
 * context, the option, and the result location.
 *
 * This requires an annoying workaround because one cannot specify a default
 * value of NULL with MIT Kerberos, since MIT Kerberos unconditionally calls
 * strdup on the default value.  There's also no way to determine if memory
 * allocation failed while parsing or while setting the default value, so we
 * don't return an error code.
 */
void
sync_config_string(krb5_context ctx, const char *opt, char **result)
{
    realm_type realm;
    char *value = NULL;

    /* Obtain the string from [appdefaults]. */
    realm = default_realm(ctx);
    krb5_appdefault_string(ctx, "krb5-sync", realm, opt, "", &value);
    free_default_realm(ctx, realm);

    /* If we got something back, store it in result. */
    if (value != NULL) {
        if (value[0] != '\0') {
            free(*result);
            *result = strdup(value);
        }
        krb5_free_string(ctx, value);
    }
}
