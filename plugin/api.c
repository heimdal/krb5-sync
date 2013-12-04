/*
 * The public APIs of the password update kadmind plugin.
 *
 * Provides the public pwupdate_init, pwupdate_close,
 * pwupdate_precommit_password, and pwupdate_postcommit_password APIs for the
 * kadmind plugin.  These APIs can also be called by command-line utilities.
 *
 * Active Directory synchronization is done in precommit and AFS kaserver
 * synchronization is done in postcommit.  The implication is that if Active
 * Directory synchronization fails, the update fails, but if AFS kaserver
 * synchronization fails, everything else still succeeds.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 *     Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007, 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <syslog.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Initialize the module.  This consists solely of loading our configuration
 * options from krb5.conf into a newly allocated struct stored in the second
 * argument to this function.  Returns 0 on success, non-zero on failure.
 * This function returns failure only if it could not allocate memory.
 */
krb5_error_code
sync_init(krb5_context ctx, kadm5_hook_modinfo **result)
{
    kadm5_hook_modinfo *config;

    /* Allocate our internal data. */
    config = calloc(1, sizeof(*config));
    if (config == NULL)
        return sync_error_system(ctx, "cannot allocate memory");

    /* Get Active Directory connection information from krb5.conf. */
    sync_config_string(ctx, "ad_keytab", &config->ad_keytab);
    sync_config_string(ctx, "ad_principal", &config->ad_principal);
    sync_config_string(ctx, "ad_realm", &config->ad_realm);
    sync_config_string(ctx, "ad_admin_server", &config->ad_admin_server);
    sync_config_string(ctx, "ad_ldap_base", &config->ad_ldap_base);

    /* Get allowed instances from krb5.conf. */
    sync_config_string(ctx, "ad_instances", &config->ad_instances);

    /* See if we're propagating an instance to the base account in AD. */
    sync_config_string(ctx, "ad_base_instance", &config->ad_base_instance);

    /* See if we're forcing queuing of all changes. */
    sync_config_boolean(ctx, "ad_queue_only", &config->ad_queue_only);

    /* Get the directory for queued changes from krb5.conf. */
    sync_config_string(ctx, "queue_dir", &config->queue_dir);

    /* Initialized.  Set data and return. */
    *result = config;
    return 0;
}


/*
 * Shut down the module.  This just means freeing our configuration struct,
 * since we don't store any other local state.
 */
void
sync_close(kadm5_hook_modinfo *config)
{
    free(config->ad_keytab);
    free(config->ad_principal);
    free(config->ad_realm);
    free(config->ad_admin_server);
    free(config->ad_base_instance);
    free(config->queue_dir);
    free(config);
}


/*
 * Given the list of allowed principals as a space-delimited string and the
 * instance of a principal, returns true if that instance is allowed and false
 * otherwise.
 */
static bool
instance_allowed(const char *allowed, const char *instance)
{
    const char *p, *i, *end;
    bool checking, okay;

    if (allowed == NULL || instance == NULL)
        return false;
    i = instance;
    end = i + strlen(instance);
    checking = true;
    okay = false;
    for (p = allowed; *p != '\0'; p++) {
        if (*p == ' ') {
            if (okay && i == end)
                break;
            okay = false;
            checking = true;
            i = instance;
        } else if (checking && (i == end || *p != *i)) {
            okay = false;
            checking = false;
            i = instance;
        } else if (checking && *p == *i) {
            okay = true;
            i++;
        }
    }
    if (okay && (*p == '\0' || *p == ' ') && i == end)
        return true;
    else
        return false;
}


/*
 * Check the principal for which we're changing a password or the enable
 * status.  Takes a flag, which is true for a password change and false for
 * other types of changes, since password changes use ad_base_instance.
 *
 * If it contains a non-null instance, we don't want to propagate the change;
 * we only want to change passwords for regular users.
 *
 * If it is a single-part principal name, ad_base_instance is set, and the
 * equivalent principal with that instance also exists, we don't propagate
 * this change because the instance's password is propagated as the base
 * account in Active Directory instead.
 *
 * Sets the allowed flag based on whether we should proceed, and returns a
 * Kerberos status code for more serious errors.  If we shouldn't proceed,
 * logs a debug-level message to syslog.
 */
static krb5_error_code
principal_allowed(kadm5_hook_modinfo *config, krb5_context ctx,
                  krb5_principal principal, bool pwchange, bool *allowed)
{
    char *display;
    krb5_error_code code;
    int ncomp;
    bool exists = false;

    /* Default to propagating. */
    *allowed = true;

    /* Get the number of components. */
    ncomp = krb5_principal_get_num_comp(ctx, principal);

    /*
     * If the principal is single-part, check against ad_base_instance.
     * Otherwise, if the principal is multi-part, check the instance.
     */
    if (pwchange && ncomp == 1 && config->ad_base_instance != NULL) {
        code = sync_instance_exists(ctx, principal, config->ad_base_instance,
                                    &exists);
        if (code != 0)
            return code;
        if (exists) {
            code = krb5_unparse_name(ctx, principal, &display);
            if (code != 0)
                display = NULL;
            syslog(LOG_DEBUG, "account synchronization skipping principal"
                   " \"%s\" for Active Directory because %s instance exists",
                   display != NULL ? display : "???",
                   config->ad_base_instance);
            if (display != NULL)
                krb5_free_unparsed_name(ctx, display);
            *allowed = false;
        }
    } else if (ncomp > 1) {
        const char *instance;

        instance = krb5_principal_get_comp_string(ctx, principal, 1);
        if (!instance_allowed(config->ad_instances, instance)) {
            code = krb5_unparse_name(ctx, principal, &display);
            if (code != 0)
                display = NULL;
            syslog(LOG_DEBUG, "account synchronization skipping principal"
                   " \"%s\" with non-null instance for Active Directory",
                   display != NULL ? display : "???");
            if (display != NULL)
                krb5_free_unparsed_name(ctx, display);
            *allowed = false;
        }
    }
    return 0;
}


/*
 * Actions to take before the password is changed in the local database.
 *
 * Push the new password to Active Directory if we have the necessary
 * configuration information and return any error it returns, but skip any
 * principals with a non-NULL instance since those are kept separately in each
 * realm.
 *
 * If a password change is already queued for this usequeue this password
 * change as well.  If the password change fails for a reason that may mean
 * that the user doesn't already exist, also queue this change.
 *
 * If the new password is NULL, that means that the keys are being randomized.
 * Currently, we can't do anything in that case, so just skip it.
 */
krb5_error_code
sync_chpass(kadm5_hook_modinfo *config, krb5_context ctx,
            krb5_principal principal, const char *password)
{
    krb5_error_code code;
    const char *message;
    bool allowed = false;

    if (config->ad_realm == NULL)
        return 0;
    if (password == NULL)
        return 0;
    code = principal_allowed(config, ctx, principal, true, &allowed);
    if (code != 0) {
        message = krb5_get_error_message(ctx, code);
        syslog(LOG_WARNING, "krb5-sync: cannot check if password change"
               " should be propagated: %s", message);
        krb5_free_error_message(ctx, message);
        return code;
    }
    if (!allowed)
        return 0;
    if (sync_queue_conflict(config, ctx, principal, "ad", "password"))
        goto queue;
    if (config->ad_queue_only)
        goto queue;
    code = sync_ad_chpass(config, ctx, principal, password);
    if (code != 0) {
        message = krb5_get_error_message(ctx, code);
        syslog(LOG_INFO, "krb5-sync: AD password change failed, queuing: %s",
               message);
        krb5_free_error_message(ctx, message);
        goto queue;
    }
    return 0;

queue:
    return sync_queue_write(config, ctx, principal, "ad", "password",
                            password);
}


/*
 * Actions to take after the account status is changed in the local database.
 *
 * Push the new account status to Active Directory if so configured, but skip
 * principals with non-NULL instances.  Return any error that it returns.
 *
 * If a status change is already queued, or if making the status change fails,
 * queue it for later processing.
 */
krb5_error_code
sync_status(kadm5_hook_modinfo *config, krb5_context ctx,
            krb5_principal principal, bool enabled)
{
    krb5_error_code code;
    const char *message;
    bool allowed;

    if (config->ad_admin_server == NULL
        || config->ad_keytab == NULL
        || config->ad_ldap_base == NULL
        || config->ad_principal == NULL
        || config->ad_realm == NULL)
        return 0;
    code = principal_allowed(config, ctx, principal, true, &allowed);
    if (code != 0) {
        message = krb5_get_error_message(ctx, code);
        syslog(LOG_WARNING, "krb5-sync: cannot check if password change"
               " should be propagated: %s", message);
        krb5_free_error_message(ctx, message);
        return code;
    }
    if (!allowed)
        return 0;
    if (sync_queue_conflict(config, ctx, principal, "ad", "enable"))
        goto queue;
    if (config->ad_queue_only)
        goto queue;
    code = sync_ad_status(config, ctx, principal, enabled);
    if (code != 0)
        goto queue;
    return 0;

queue:
    return sync_queue_write(config, ctx, principal, "ad",
                            enabled ? "enable" : "disable", NULL);
}
