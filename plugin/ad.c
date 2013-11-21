/*
 * Active Directory synchronization functions.
 *
 * Implements the interface that talks to Active Directory for both password
 * changes and for account status updates.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
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
        if (config->c == NULL)                                          \
            return sync_error_config(ctx, "configuration setting %s"    \
                                     " missing", STRINGIFY(c));         \
    } while (0)


/*
 * Given the plugin options, a Kerberos context, and a pointer to krb5_ccache
 * storage, initialize a memory cache using the configured keytab to obtain
 * initial credentials.  Returns a Kerberos status code.
 */
static krb5_error_code
get_creds(kadm5_hook_modinfo *config, krb5_context ctx, krb5_ccache *cc)
{
    krb5_error_code code;
    krb5_keytab kt = NULL;
    krb5_principal princ = NULL;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_creds creds;
    bool creds_valid = false;
    const char *realm UNUSED;

    /* Initialize the credential cache pointer to NULL. */
    *cc = NULL;

    /* Ensure the configuration is sane. */
    CHECK_CONFIG(ad_keytab);
    CHECK_CONFIG(ad_principal);

    /* Resolve the keytab and principal used to get credentials. */
    code = krb5_kt_resolve(ctx, config->ad_keytab, &kt);
    if (code != 0)
        goto fail;
    code = krb5_parse_name(ctx, config->ad_principal, &princ);
    if (code != 0)
        goto fail;

    /* Set our credential acquisition options. */
    code = krb5_get_init_creds_opt_alloc(ctx, &opts);
    if (code != 0)
        goto fail;
    realm = krb5_principal_get_realm(ctx, princ);
    krb5_get_init_creds_opt_set_default_flags(ctx, "krb5-sync", realm, opts);

    /* Obtain credentials. */
    memset(&creds, 0, sizeof(creds));
    code = krb5_get_init_creds_keytab(ctx, &creds, princ, kt, 0, NULL, opts);
    if (code != 0)
        goto fail;
    krb5_get_init_creds_opt_free(ctx, opts);
    opts = NULL;
    krb5_kt_close(ctx, kt);
    kt = NULL;
    creds_valid = true;

    /* Open and initialize the credential cache. */
    code = krb5_cc_resolve(ctx, CACHE_NAME, cc);
    if (code != 0)
        goto fail;
    code = krb5_cc_initialize(ctx, *cc, princ);
    if (code != 0)
        code = krb5_cc_store_cred(ctx, *cc, &creds);
    if (code != 0) {
        krb5_cc_close(ctx, *cc);
        *cc = NULL;
        goto fail;
    }

    /* Clean up and return success. */
    krb5_free_cred_contents(ctx, &creds);
    krb5_free_principal(ctx, princ);
    return 0;

fail:
    if (kt != NULL)
        krb5_kt_close(ctx, kt);
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    if (opts != NULL)
        krb5_get_init_creds_opt_free(ctx, opts);
    if (creds_valid)
        krb5_free_cred_contents(ctx, &creds);
    return code;
}


/*
 * Given the krb5_principal from kadmind, convert it to the corresponding
 * principal in Active Directory.  This may involve removing ad_base_instance
 * and always involves changing the realm.  Returns a Kerberos error code.
 */
static krb5_error_code
get_ad_principal(kadm5_hook_modinfo *config, krb5_context ctx,
                 krb5_const_principal principal, krb5_principal *ad_principal)
{
    krb5_error_code code;
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
            code = krb5_build_principal(ctx, ad_principal,
                                       strlen(config->ad_realm),
                                       config->ad_realm, base, (char *) 0);
            if (code != 0)
                return code;
        }
    }

    /* Otherwise, copy the principal and set the realm. */
    if (*ad_principal == NULL) {
        code = krb5_copy_principal(ctx, principal, ad_principal);
        if (code != 0)
            return code;
        krb5_principal_set_realm(ctx, *ad_principal, config->ad_realm);
    }
    return 0;
}


/*
 * Push a password change to Active Directory.  Takes the module
 * configuration, a Kerberos context, the principal whose password is being
 * changed (we will have to change the realm), and the new password and its
 * length.  Returns a Kerberos error code.
 */
krb5_error_code
sync_ad_chpass(kadm5_hook_modinfo *config, krb5_context ctx,
               krb5_principal principal, const char *password)
{
    krb5_error_code code;
    char *target = NULL;
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    int result_code;
    krb5_data result_code_string, result_string;

    /* Ensure the configuration is sane. */
    CHECK_CONFIG(ad_realm);

    /* Get the credentials we'll use to make the change in AD. */
    code = get_creds(config, ctx, &ccache);
    if (code != 0)
        return code;

    /* Get the corresponding AD principal. */
    code = get_ad_principal(config, ctx, principal, &ad_principal);
    if (code != 0)
        goto done;

    /* This is just for logging purposes. */
    code = krb5_unparse_name(ctx, ad_principal, &target);
    if (code != 0)
        goto done;

    /* Do the actual password change and record any error. */
    code = krb5_set_password_using_ccache(ctx, ccache, (char *) password,
                                          ad_principal, &result_code,
                                          &result_code_string, &result_string);
    if (code != 0)
        goto done;
    if (result_code != 0) {
        code = sync_error_generic(ctx, "password change failed for %s: (%d)"
                                  " %.*s%s%.*s", target, result_code,
                                  result_code_string.length,
                                  (char *) result_code_string.data,
                                  result_string.length ? ": " : "",
                                  result_string.length,
                                  (char *) result_string.data);
        goto done;
    }
    free(result_string.data);
    free(result_code_string.data);
    syslog(LOG_INFO, "krb5-sync: %s password changed", target);

done:
    krb5_cc_destroy(ctx, ccache);
    if (target != NULL)
        krb5_free_unparsed_name(ctx, target);
    if (ad_principal != NULL)
        krb5_free_principal(ctx, ad_principal);
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
krb5_error_code
sync_ad_status(kadm5_hook_modinfo *config, krb5_context ctx,
               krb5_principal principal, bool enabled)
{
    krb5_ccache ccache;
    krb5_principal ad_principal = NULL;
    LDAP *ld = NULL;
    LDAPMessage *res = NULL;
    LDAPMod mod, *mod_array[2];
    char *dn;
    char *ldapuri = NULL, *ldapdn = NULL, *control = NULL, *target = NULL;
    struct berval **vals = NULL;
    char *value;
    const char *attrs[] = { "userAccountControl", NULL };
    char *strvals[2];
    int option;
    unsigned int acctcontrol;
    krb5_error_code code;

    /* Ensure the configuration is sane. */
    CHECK_CONFIG(ad_admin_server);
    CHECK_CONFIG(ad_ldap_base);

    /* Get the credentials we'll use to make the change in AD. */
    code = get_creds(config, ctx, &ccache);
    if (code != 0)
        return code;

    /*
     * Point SASL at the memory cache we're about to create.  This is changing
     * the global environment for kadmind and is therefore quite ugly, but
     * should hopefully be harmless.  Ideally OpenLDAP should provide some way
     * of calling through to Cyrus SASL to set the ticket cache, but that's
     * hard.
     */
    if (putenv((char *) "KRB5CCNAME=" CACHE_NAME) != 0) {
        code = sync_error_system(ctx, "putenv of KRB5CCNAME failed");
        goto done;
    }

    /* Now, bind to the directory server using GSSAPI. */
    if (asprintf(&ldapuri, "ldap://%s", config->ad_admin_server) < 0) {
        code = sync_error_system(ctx, "cannot allocate memory");
        goto done;
    }
    code = ldap_initialize(&ld, ldapuri);
    if (code != LDAP_SUCCESS) {
        code = sync_error_ldap(ctx, code, "LDAP initialization failed");
        goto done;
    }
    option = LDAP_VERSION3;
    code = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &option);
    if (code != LDAP_SUCCESS) {
        code = sync_error_ldap(ctx, code, "LDAP protocol selection failed");
        goto done;
    }
    code = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL,
                                       LDAP_SASL_QUIET, ad_interact_sasl,
                                       NULL);
    if (code != LDAP_SUCCESS) {
        code = sync_error_ldap(ctx, code, "LDAP bind failed");
        goto done;
    }

    /*
     * Since all we know is the local principal, we have to convert that to
     * the AD principal and then query Active Directory via LDAP to get back
     * the CN for the user to construct the full DN.
     */
    code = get_ad_principal(config, ctx, principal, &ad_principal);
    if (code != 0)
        goto done;
    code = krb5_unparse_name(ctx, ad_principal, &target);
    if (code != 0)
        goto done;
    if (asprintf(&ldapdn, "(userPrincipalName=%s)", target) < 0) {
        code = sync_error_system(ctx, "cannot allocate memory");
        goto done;
    }
    code = ldap_search_ext_s(ld, config->ad_ldap_base, LDAP_SCOPE_SUBTREE,
                             ldapdn, (char **) attrs, 0, NULL, NULL, NULL, 0,
                             &res);
    if (code != LDAP_SUCCESS) {
        code = sync_error_ldap(ctx, code, "LDAP search for \"%s\" failed",
                               ldapdn);
        goto done;
    }
    if (ldap_count_entries(ld, res) == 0) {
        code = sync_error_generic(ctx, "user \"%s\" not found via LDAP",
                                  target);
        goto done;
    }
    res = ldap_first_entry(ld, res);
    dn = ldap_get_dn(ld, res);
    if (ldap_msgtype(res) != LDAP_RES_SEARCH_ENTRY) {
        code = sync_error_generic(ctx, "expected LDAP msgtype of"
                                  " RES_SEARCH_ENTRY (0x61), but got type %x"
                                  " instead", ldap_msgtype(res));
        goto done;
    }
    vals = ldap_get_values_len(ld, res, "userAccountControl");
    if (ldap_count_values_len(vals) != 1) {
        code = sync_error_generic(ctx, "expected one value for"
                                  " userAccountControl for user \"%s\" and"
                                  " got %d", target,
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
        code = sync_error_system(ctx, "cannot allocate memory");
        goto done;
    }
    memcpy(value, vals[0]->bv_val, vals[0]->bv_len);
    value[vals[0]->bv_len] = '\0';
    if (sscanf(value, "%u", &acctcontrol) != 1) {
        free(value);
        code = sync_error_generic(ctx, "unable to parse userAccountControl"
                                  " for user \"%s\" (%s)", target, value);
        goto done;
    }
    free(value);
    if (enabled)
        acctcontrol &= ~UF_ACCOUNTDISABLE;
    else
        acctcontrol |= UF_ACCOUNTDISABLE;
    memset(&mod, 0, sizeof(mod));
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = (char *) "userAccountControl";
    if (asprintf(&control, "%u", acctcontrol) < 0) {
        code = sync_error_system(ctx, "cannot allocate memory");
        goto done;
    }
    strvals[0] = control;
    strvals[1] = NULL;
    mod.mod_vals.modv_strvals = strvals;
    mod_array[0] = &mod;
    mod_array[1] = NULL;
    code = ldap_modify_ext_s(ld, dn, mod_array, NULL, NULL);
    if (code != LDAP_SUCCESS) {
        code = sync_error_ldap(ctx, code, "LDAP modification for user \"%s\""
                               " failed", target);
        goto done;
    }

    /* Success. */
    code = 0;
    syslog(LOG_INFO, "successfully %s account %s",
           enabled ? "enabled" : "disabled", target);

done:
    free(ldapuri);
    free(ldapdn);
    free(control);
    krb5_cc_destroy(ctx, ccache);
    if (target != NULL)
        krb5_free_unparsed_name(ctx, target);
    if (res != NULL)
        ldap_msgfree(res);
    if (vals != NULL)
        ldap_value_free_len(vals);
    if (ld == NULL)
        ldap_unbind_ext_s(ld, NULL, NULL);
    return code;
}
