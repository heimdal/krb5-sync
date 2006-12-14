/*
 * ad.c
 *
 * Active Directory synchronization functions.
 *
 * Implements the interface that talks to Active Directory for both password
 * changes and for account status updates.
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <plugin/internal.h>

/* The memory cache name used to store credentials for AD. */
#define CACHE_NAME "MEMORY:krb5_sync"

/*
 * Given the plugin options, a Kerberos context, a pointer to krb5_ccache
 * storage, and the buffer into which to store an error message if any,
 * initialize a memory cache using the configured keytab to obtain initial
 * credentials.  Also set the KRB5CCNAME environment variable for the use of
 * SASL later for LDAP calls.  This is quite ugly since it changes the whole
 * kadmind process, but it's hopefully harmless.  Return 0 on success,
 * non-zero on failure.
 */
static int
get_creds(struct plugin_config *config, krb5_context ctx, krb5_ccache *cc,
          char *errstr, int errstrlen)
{
    krb5_keytab kt;
    krb5_creds creds;
    krb5_principal princ;
    krb5_get_init_creds_opt opts;
    krb5_error_code ret;

    ret = krb5_kt_resolve(ctx, config->ad_keytab, &kt);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to resolve keytab \"%s\": %s",
                 config->ad_keytab, error_message(ret));
        return 1;
    }
    ret = krb5_parse_name(ctx, config->ad_principal, &princ);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to parse principal \"%s\": %s",
                 config->ad_principal, error_message(ret));
        return 1;
    }
    krb5_get_init_creds_opt_init(&opts);
    memset(&creds, 0, sizeof(creds));
    ret = krb5_get_init_creds_keytab(ctx, &creds, princ, kt, 0, NULL, &opts);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to get initial credentials: %s",
                 error_message(ret));
        return 1;
    }
    ret = krb5_kt_close(ctx, kt);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to close keytab: %s",
                 error_message(ret));
        return 1;
    }
    ret = krb5_cc_resolve(ctx, CACHE_NAME, cc);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to resolve memory cache: %s",
                 error_message(ret));
        return 1;
    }
    ret = krb5_cc_initialize(ctx, *cc, princ);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to initialize memory cache: %s",
                 error_message(ret));
        return 1;
    }
    ret = krb5_cc_store_cred(ctx, *cc, &creds);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to store credentials: %s",
                 error_message(ret));
        return 1;
    }
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    return 0;
}

/*
 * Push a password change to Active Directory.  Takes the module
 * configuration, a Kerberos context, the principal whose password is being
 * changed (we will have to change the realm), the new password and its
 * length, and a buffer into which to put error messages and its length.
 */
int
pwupdate_ad_change(struct plugin_config *config, krb5_context ctx,
                   krb5_principal principal, char *password, int pwlen,
                   char *errstr, int errstrlen)
{
    krb5_error_code ret;
    char *target = NULL;
    krb5_ccache ccache;
    int result_code;
    krb5_data result_code_string, result_string;
    int code = 0;

    if (get_creds(config, ctx, &ccache, errstr, errstrlen) != 0)
        return 1;

    /* This is just for logging purposes. */
    ret = krb5_unparse_name(ctx, principal, &target);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to parse target principal: %s",
                 error_message(ret));
        return 1;
    }

    /*
     * Change the principal over to the AD realm.  Right now, this is all the
     * rewriting or mapping that we do.  If later we need to do more
     * comprehensive mapping, this is where we'd do it.
     */
    krb5_set_principal_realm(ctx, principal, config->ad_realm);

    /* Do the actual password change. */
    ret = krb5_set_password_using_ccache(ctx, ccache, password, principal,
                                         &result_code, &result_code_string,
                                         &result_string);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "password change failed for %s in %s: %s",
                 target, config->ad_realm, error_message(ret));
        code = 1;
        goto done;
    }
    if (result_code != 0) {
        snprintf(errstr, errstrlen, "password change failed for %s in %s:"
                 " %.*s%s%.*s", target, config->ad_realm,
                 result_code_string.length, result_code_string.data, 
                 result_string.length ? ": " : "", 
                 result_string.length, result_string.data); 
        code = 2;
        goto done;
    }
    free(result_string.data);
    free(result_code_string.data);
    syslog(LOG_INFO, "pwupdate: %s password changed in %s", target,
           config->ad_realm);
    snprintf(errstr, errstrlen, "Password changed");

done:
    krb5_free_unparsed_name(ctx, target);
    krb5_cc_destroy(ctx, ccache);
    return code;
}
