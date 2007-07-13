/*
 * ad.c
 *
 * Active Directory synchronization functions.
 *
 * Implements the interface that talks to Active Directory for both password
 * changes and for account status updates.
 */

#include <com_err.h>
#include <errno.h>
#include <krb5.h>
#include <ldap.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <plugin/internal.h>

/* The memory cache name used to store credentials for AD. */
#define CACHE_NAME "MEMORY:krb5_sync"

/* The flag value used in Active Directory to indicate a disabled account. */
#define UF_ACCOUNTDISABLE 0x02

/*
 * Given the plugin options, a Kerberos context, a pointer to krb5_ccache
 * storage, and the buffer into which to store an error message if any,
 * initialize a memory cache using the configured keytab to obtain initial
 * credentials.  Return 0 on success, non-zero on failure.
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
 * Given the krb5_principal from kadmind, convert it to the corresponding
 * principal in Active Directory.  Returns 0 on success and a Kerberos error
 * code on failure.  Currently, all this does is change the realm.
 */
static krb5_error_code
get_ad_principal(krb5_context ctx, krb5_const_principal principal,
                 krb5_principal *ad_principal)
{
    ret = krb5_copy_principal(ctx, principal, ad_principal);
    if (ret != 0)
        return ret;
    krb5_set_principal_realm(ctx, *ad_principal, config->ad_realm);
    return 0;
}

/*
 * Push a password change to Active Directory.  Takes the module
 * configuration, a Kerberos context, the principal whose password is being
 * changed (we will have to change the realm), the new password and its
 * length, and a buffer into which to put error messages and its length.
 *
 * Returns 1 for any general failure, 2 if the password change was rejected by
 * the remote system, and 3 if the password change was rejected for a reason
 * that may mean that the user doesn't exist.
 */
int
pwupdate_ad_change(struct plugin_config *config, krb5_context ctx,
                   krb5_principal principal, char *password,
                   int pwlen UNUSED, char *errstr, int errstrlen)
{
    krb5_error_code ret;
    char *target = NULL;
    char *p;
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    int result_code;
    krb5_data result_code_string, result_string;
    int code = 0;

    if (get_creds(config, ctx, &ccache, errstr, errstrlen) != 0)
        return 1;

    /* Get the corresponding Active Directory principal. */
    ret = get_ad_principal(ctx, principal, &ad_principal);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to get AD principal: %s",
                 error_message(ret));
        code = 1;
        goto done;
    }

    /* Do the actual password change. */
    ret = krb5_set_password_using_ccache(ctx, ccache, password, ad_principal,
                                         &result_code, &result_code_string,
                                         &result_string);
    krb5_free_principal(ctx, ad_principal);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "password change failed for %s in %s: %s",
                 target, config->ad_realm, error_message(ret));
        code = 1;
        goto done;
    }
    if (result_code != 0) {
        snprintf(errstr, errstrlen, "password change failed for %s in %s:"
                 " (%d) %.*s%s%.*s", target, config->ad_realm, result_code,
                 result_code_string.length, result_code_string.data, 
                 result_string.length ? ": " : "", 
                 result_string.length, result_string.data); 
        code = 3;
        goto done;
    }
    free(result_string.data);
    free(result_code_string.data);
    syslog(LOG_INFO, "pwupdate: %s password changed", target);
    snprintf(errstr, errstrlen, "Password changed");

done:
    if (target != NULL)
        krb5_free_unparsed_name(ctx, target);
    krb5_cc_destroy(ctx, ccache);
    return code;
}

/*
 * Empty SASL callback function to satisfy the requirements of the LDAP SASL
 * bind interface.  Hopefully it won't need anything.
 */
static int
ad_interact_sasl(LDAP *ld UNUSED, unsigned flags UNUSED,
                 void *defaults UNUSED, void *interact UNUSED)
{
    return 0;
}

/*
 * Change the status of an account in Active Directory.  Takes the plugin
 * configuration, a Kerberos context, the principal whose status changed (only
 * the principal name is used, ignoring the realm), a flag saying whether the
 * account is enabled, and a buffer into which to put error messages and its
 * length.
 */
int pwupdate_ad_status(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, int enabled, char *errstr,
                       int errstrlen)
{
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    LDAP *ld;
    LDAPMessage *res = NULL;
    LDAPMod mod, *mod_array[2];
    char ldapuri[256], ldapbase[256], ldapdn[256], *dname, *lb, *dn, *p;
    char *target = NULL;
    char **vals = NULL;
    const char *attrs[] = { "userAccountControl", NULL };
    char *strvals[2];
    int option, ret;
    unsigned int acctcontrol;
    int code = 1;

    if (get_creds(config, ctx, &ccache, errstr, errstrlen) != 0)
        return 1;

    /*
     * Point SASL at the memory cache we're about to create.  This is changing
     * the global environment for kadmind and is therefore quite ugly, but
     * should hopefully be harmless.  Ideally OpenLDAP should provide some way
     * of calling through to Cyrus SASL to set the ticket cache, but that's
     * hard.
     */
    if (putenv((char *) "KRB5CCNAME=" CACHE_NAME) != 0) {
        snprintf(errstr, errstrlen, "putenv of KRB5CCNAME failed: %s",
                 strerror(errno));
        return 1;
    }

    /* Now, bind to the directory server using GSSAPI. */
    snprintf(ldapuri, sizeof(ldapuri), "ldap://%s", config->ad_admin_server);
    ret = ldap_initialize(&ld, ldapuri);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP initialization failed: %s",
                 ldap_err2string(ret));
        return 1;
    }
    option = LDAP_VERSION3;
    ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &option);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP protocol selection failed: %s",
                 ldap_err2string(ret));
        goto done;
    }
    ret = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL,
                                       LDAP_SASL_QUIET, ad_interact_sasl,
                                       NULL);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP bind failed: %s",
                 ldap_err2string(ret));
        goto done;
    }

    /*
     * Convert the domain name to a DN; since we're always working in the
     * Accounts tree, just start out with that.  This may be
     * Stanford-specific; if so, we'll need to add the base DN as a
     * configuration option.
     */
    memset(ldapbase, 0, sizeof(ldapbase));
    strcpy(ldapbase, "ou=Accounts,dc=");
    lb = ldapbase + strlen(ldapbase);
    for (dname = config->ad_realm; *dname != '\0'; dname++) {
        if (*dname == '.') {
            strcpy(lb, ",dc=");
            lb += 4;
        } else
            *lb++ = *dname;
        if (strlen(ldapbase) > sizeof(ldapbase) - 5)
            break;
    }

    /*
     * Since all we know is the local principal, we have to convert that to
     * the AD principal and then query Active Directory via LDAP to get back
     * the CN for the user to construct the full DN.
     */
    ret = get_ad_principal(ctx, principal, &ad_principal);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to get AD principal: %s",
                 error_message(ret));
        goto done;
    }
    ret = krb5_unparse_name(ctx, ad_principal, &target);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "unable to parse target principal: %s",
                 error_message(ret));
        goto done;
    }
    snprintf(ldapdn, sizeof(ldapdn), "(userPrincipalName=%s)", target);
    ret = ldap_search_s(ld, ldapbase, LDAP_SCOPE_SUBTREE, ldapdn,
                        (char **) attrs, 0, &res);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP search on \"%s\" failed: %s",
                 ldapdn, ldap_err2string(ret));
        goto done;
    }
    if (ldap_count_entries(ld, res) == 0) {
        snprintf(errstr, errstrlen, "user \"%s\" not found in %s",
                 target, config->ad_realm);
        goto done;
    }
    res = ldap_first_entry(ld, res);
    dn = ldap_get_dn(ld, res);
    if (ldap_msgtype(res) != LDAP_RES_SEARCH_ENTRY) {
        snprintf(errstr, errstrlen, "expected msgtype of RES_SEARCH_ENTRY"
                 " (0x61), but got type %x instead", ldap_msgtype(res));
        goto done;
    }
    vals = ldap_get_values(ld, res, "userAccountControl");
    if (ldap_count_values(vals) != 1) {
        snprintf(errstr, errstrlen, "expected one value for"
                 " userAccountControl for user \"%s\" and got %d", target,
                 ldap_count_values(vals));
        goto done;
    }

    /*
     * Okay, we've found the user and everything looks normal.  Parse the
     * current flag value and modify it according to the enable, flag, and
     * then push back the modified value.
     */
    if (sscanf(vals[0], "%u", &acctcontrol) != 1) {
        snprintf(errstr, errstrlen, "unable to parse userAccountControl for"
                 " user \"%s\" (%s)", target, vals[0]);
        goto done;
    }
    if (enabled) {
        acctcontrol &= ~UF_ACCOUNTDISABLE;
    } else {
        acctcontrol |= UF_ACCOUNTDISABLE;
    }
    memset(&mod, 0, sizeof(mod));
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = (char *) "userAccountControl";
    snprintf(ldapdn, sizeof(ldapdn), "%u", acctcontrol);
    strvals[0] = ldapdn;
    strvals[1] = NULL;
    mod.mod_vals.modv_strvals = strvals;
    mod_array[0] = &mod;
    mod_array[1] = NULL;
    ret = ldap_modify_s(ld, dn, mod_array);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP modification for user \"%s\""
                 " failed: %s", target, ldap_err2string(ret));
        goto done;
    }

    /* Success. */
    code = 0;
    syslog(LOG_INFO, "successfully set account %s@%s to %s", target,
           config->ad_realm, enabled ? "enabled" : "disabled");

done:
    if (target != NULL)
        free(target);
    if (res != NULL)
        ldap_msgfree(res);
    if (vals != NULL)
        ldap_value_free(vals);
    ldap_unbind_s(ld);
    return code;
}
