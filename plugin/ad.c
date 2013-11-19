/*
 * Active Directory synchronization functions.
 *
 * Implements the interface that talks to Active Directory for both password
 * changes and for account status updates.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 *     Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007, 2010, 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <lber.h>
#include <ldap.h>
#include <syslog.h>

#include <plugin/internal.h>
#include <util/macros.h>

/* The memory cache name used to store credentials for AD. */
#define CACHE_NAME "MEMORY:krb5_sync"

/* The flag value used in Active Directory to indicate a disabled account. */
#define UF_ACCOUNTDISABLE 0x02


/*
 * Check a specific configuratino attribute to ensure that it's set and, if
 * not, set the error string and return.  Assumes that the configuration
 * struct is config and errstr and errstrlen are declared in the current
 * scope.
 */
#define STRINGIFY(s) #s
#define CHECK_CONFIG(c)                                                 \
    do {                                                                \
        if (config->c == NULL) {                                        \
            pwupdate_set_error(errstr, errstrlen, NULL, 0,              \
                               "configuration setting %s missing",      \
                               STRINGIFY(c));                           \
            return 1;                                                   \
        }                                                               \
    } while (0)


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
    krb5_get_init_creds_opt *opts;
    krb5_error_code ret;
    const char *realm UNUSED;

    CHECK_CONFIG(ad_keytab);
    CHECK_CONFIG(ad_principal);

    ret = krb5_kt_resolve(ctx, config->ad_keytab, &kt);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to resolve keytab \"%s\"",
                           config->ad_keytab);
        return 1;
    }
    ret = krb5_parse_name(ctx, config->ad_principal, &princ);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to parse principal \"%s\"",
                           config->ad_principal);
        return 1;
    }
    ret = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "error allocating credential options");
        return 1;
    }
    realm = krb5_principal_get_realm(ctx, princ);
    krb5_get_init_creds_opt_set_default_flags(ctx, "krb5-sync", realm, opts);
    memset(&creds, 0, sizeof(creds));
    ret = krb5_get_init_creds_keytab(ctx, &creds, princ, kt, 0, NULL, opts);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to get initial credentials");
        krb5_get_init_creds_opt_free(ctx, opts);
        return 1;
    }
    krb5_get_init_creds_opt_free(ctx, opts);
    ret = krb5_kt_close(ctx, kt);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to close keytab");
        return 1;
    }
    ret = krb5_cc_resolve(ctx, CACHE_NAME, cc);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to resolve memory cache");
        return 1;
    }
    ret = krb5_cc_initialize(ctx, *cc, princ);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to initialize memory cache");
        return 1;
    }
    ret = krb5_cc_store_cred(ctx, *cc, &creds);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to store credentials");
        return 1;
    }
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    return 0;
}


/*
 * Given the krb5_principal from kadmind, convert it to the corresponding
 * principal in Active Directory.  This may involve removing ad_base_instance
 * and always involves changing the realm.  Returns 0 on success and a
 * Kerberos error code on failure.
 */
static krb5_error_code
get_ad_principal(krb5_context ctx, struct plugin_config *config,
                 krb5_const_principal principal, krb5_principal *ad_principal)
{
    krb5_error_code ret;
    int ncomp;

    /*
     * Set ad_principal to NULL to start.  We fall back on copy and realm
     * setting if we don't have to build it, and use whether it's NULL as a
     * flag.
     */
    *ad_principal = NULL;

    /* Get the number of components. */
    ncomp = krb5_principal_get_num_comp(ctx, principal);

    /* See if this is an ad_base_instance principal that needs a rewrite. */
    if (config->ad_base_instance != NULL && ncomp == 2) {
        const char *base, *instance;

        instance = krb5_principal_get_comp_string(ctx, principal, 1);
        if (strcmp(instance, config->ad_base_instance) == 0) {
            base = krb5_principal_get_comp_string(ctx, principal, 0);
            ret = krb5_build_principal(ctx, ad_principal,
                                       strlen(config->ad_realm),
                                       config->ad_realm, base, (char *) 0);
            if (ret != 0)
                return ret;
        }
    }

    /* Otherwise, copy the principal and set the realm. */
    if (*ad_principal == NULL) {
        ret = krb5_copy_principal(ctx, principal, ad_principal);
        if (ret != 0)
            return ret;
        krb5_principal_set_realm(ctx, *ad_principal, config->ad_realm);
    }
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
                   krb5_principal principal, const char *password,
                   int pwlen UNUSED, char *errstr, int errstrlen)
{
    krb5_error_code ret;
    char *target = NULL;
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    int result_code;
    krb5_data result_code_string, result_string;
    int code = 0;

    CHECK_CONFIG(ad_realm);

    if (get_creds(config, ctx, &ccache, errstr, errstrlen) != 0)
        return 1;

    /* Get the corresponding Active Directory principal. */
    ret = get_ad_principal(ctx, config, principal, &ad_principal);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to get AD principal");
        code = 1;
        goto done;
    }

    /* This is just for logging purposes. */
    ret = krb5_unparse_name(ctx, ad_principal, &target);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to parse target principal");
        code = 1;
        goto done;
    }

    /* Do the actual password change. */
    ret = krb5_set_password_using_ccache(ctx, ccache, (char *) password,
                                         ad_principal, &result_code,
                                         &result_code_string, &result_string);
    krb5_free_principal(ctx, ad_principal);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "password change failed for %s in %s",
                           target, config->ad_realm);
        code = 3;
        goto done;
    }
    if (result_code != 0) {
        snprintf(errstr, errstrlen, "password change failed for %s in %s:"
                 " (%d) %.*s%s%.*s", target, config->ad_realm, result_code,
                 result_code_string.length, (char *) result_code_string.data,
                 result_string.length ? ": " : "",
                 result_string.length, (char *) result_string.data);
        code = 3;
        goto done;
    }
    free(result_string.data);
    free(result_code_string.data);
    syslog(LOG_INFO, "pwupdate: %s password changed", target);
    strlcpy(errstr, "Password changed", errstrlen);

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
int
pwupdate_ad_status(struct plugin_config *config, krb5_context ctx,
                   krb5_principal principal, int enabled, char *errstr,
                   int errstrlen)
{
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    LDAP *ld;
    LDAPMessage *res = NULL;
    LDAPMod mod, *mod_array[2];
    char ldapuri[256], ldapbase[256], ldapdn[256], *dname, *lb, *end, *dn;
    char *target = NULL;
    struct berval **vals = NULL;
    char *value;
    const char *attrs[] = { "userAccountControl", NULL };
    char *strvals[2];
    int option, ret;
    unsigned int acctcontrol;
    int code = 1;

    CHECK_CONFIG(ad_admin_server);
    CHECK_CONFIG(ad_realm);

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
     * Convert the domain name to a DN.  The default is ou=Accounts, which
     * is what Stanford uses, but the base DN prior to the dc portion for
     * the realm can be changed with a configuration option.
     */
    memset(ldapbase, 0, sizeof(ldapbase));
    if (config->ad_ldap_base == NULL)
        strlcpy(ldapbase, "ou=Accounts,dc=", sizeof(ldapbase));
    else {
        strlcpy(ldapbase, config->ad_ldap_base, sizeof(ldapbase));
        strlcat(ldapbase, ",dc=", sizeof(ldapbase));
    }
    lb = ldapbase + strlen(ldapbase);
    end = ldapbase + sizeof(ldapbase) - 1;
    for (dname = config->ad_realm; lb < end && *dname != '\0'; dname++) {
        if (*dname == '.') {
            *lb = '\0';
            strlcat(ldapbase, ",dc=", sizeof(ldapbase));
            lb += 4;
        } else {
            *lb++ = *dname;
        }
    }

    /*
     * Since all we know is the local principal, we have to convert that to
     * the AD principal and then query Active Directory via LDAP to get back
     * the CN for the user to construct the full DN.
     */
    ret = get_ad_principal(ctx, config, principal, &ad_principal);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to get AD principal");
        goto done;
    }
    ret = krb5_unparse_name(ctx, ad_principal, &target);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, ctx, ret,
                           "unable to parse target principal");
        goto done;
    }
    snprintf(ldapdn, sizeof(ldapdn), "(userPrincipalName=%s)", target);
    ret = ldap_search_ext_s(ld, ldapbase, LDAP_SCOPE_SUBTREE, ldapdn,
                            (char **) attrs, 0, NULL, NULL, NULL, 0, &res);
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
    vals = ldap_get_values_len(ld, res, "userAccountControl");
    if (ldap_count_values_len(vals) != 1) {
        snprintf(errstr, errstrlen, "expected one value for"
                 " userAccountControl for user \"%s\" and got %d", target,
                 ldap_count_values_len(vals));
        goto done;
    }

    /*
     * Okay, we've found the user and everything looks normal.  Parse the
     * current flag value and modify it according to the enable, flag, and
     * then push back the modified value.
     */
    value = malloc(vals[0]->bv_len + 1);
    if (value == NULL) {
        snprintf(errstr, errstrlen, "cannot allocate memory: %s",
                 strerror(errno));
        goto done;
    }
    memcpy(value, vals[0]->bv_val, vals[0]->bv_len);
    value[vals[0]->bv_len] = '\0';
    if (sscanf(value, "%u", &acctcontrol) != 1) {
        free(value);
        snprintf(errstr, errstrlen, "unable to parse userAccountControl for"
                 " user \"%s\" (%s)", target, value);
        goto done;
    }
    free(value);
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
    ret = ldap_modify_ext_s(ld, dn, mod_array, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        snprintf(errstr, errstrlen, "LDAP modification for user \"%s\""
                 " failed: %s", target, ldap_err2string(ret));
        goto done;
    }

    /* Success. */
    code = 0;
    syslog(LOG_INFO, "successfully set account %s to %s", target,
           enabled ? "enabled" : "disabled");

done:
    if (target != NULL)
        krb5_free_unparsed_name(ctx, target);
    if (res != NULL)
        ldap_msgfree(res);
    if (vals != NULL)
        ldap_value_free_len(vals);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return code;
}
