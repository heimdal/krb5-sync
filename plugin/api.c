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
pwupdate_init(kadm5_hook_modinfo **result, krb5_context ctx)
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
pwupdate_close(kadm5_hook_modinfo *config)
{
    if (config->ad_keytab != NULL)
        free(config->ad_keytab);
    if (config->ad_principal != NULL)
        free(config->ad_principal);
    if (config->ad_realm != NULL)
        free(config->ad_realm);
    if (config->ad_admin_server != NULL)
        free(config->ad_admin_server);
    if (config->ad_base_instance != NULL)
        free(config->ad_base_instance);
    if (config->queue_dir != NULL)
        free(config->queue_dir);
    free(config);
}


/*
 * Given the list of allowed principals as a space-delimited string and the
 * instance of a principal, returns true if that instance is allowed and false
 * otherwise.
 */
static int
instance_allowed(const char *allowed, const char *instance)
{
    const char *p, *i, *end;
    int checking, okay;

    if (allowed == NULL || instance == NULL)
        return 0;
    i = instance;
    end = i + strlen(instance);
    checking = 1;
    okay = 0;
    for (p = allowed; *p != '\0'; p++) {
        if (*p == ' ') {
            if (okay && i == end)
                break;
            okay = 0;
            checking = 1;
            i = instance;
        } else if (checking && (i == end || *p != *i)) {
            okay = 0;
            checking = 0;
            i = instance;
        } else if (checking && *p == *i) {
            okay = 1;
            i++;
        }
    }
    if (okay && (*p == '\0' || *p == ' ') && i == end)
        return 1;
    else
        return 0;
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
 * Returns true if we should proceed, false otherwise.  If we shouldn't
 * proceed, logs a debug-level message to syslog.
 */
static int
principal_allowed(kadm5_hook_modinfo *config, krb5_context ctx,
                  krb5_principal principal, int pwchange)
{
    char *display;
    krb5_error_code code;
    int ncomp, okay;

    /* Get the number of components. */
    ncomp = krb5_principal_get_num_comp(ctx, principal);

    /*
     * If the principal is single-part, check against ad_base_instance.
     * Otherwise, if the principal is multi-part, check the instance.
     */
    if (pwchange && ncomp == 1 && config->ad_base_instance != NULL) {
        okay = !pwupdate_instance_exists(config, ctx, principal,
                                         config->ad_base_instance);
        if (!okay) {
            code = krb5_unparse_name(ctx, principal, &display);
            if (code != 0)
                display = NULL;
            syslog(LOG_DEBUG, "account synchronization skipping principal"
                   " \"%s\" for Active Directory because %s instance exists",
                   display != NULL ? display : "???",
                   config->ad_base_instance);
            if (display != NULL)
                krb5_free_unparsed_name(ctx, display);
        }
        return okay;
    } else if (ncomp > 1) {
        const char *instance;

        instance = krb5_principal_get_comp_string(ctx, principal, 1);
        if (instance_allowed(config->ad_instances, instance))
            return 1;
        code = krb5_unparse_name(ctx, principal, &display);
        if (code != 0)
            display = NULL;
        syslog(LOG_DEBUG, "account synchronization skipping principal \"%s\""
               " with non-null instance for Active Directory",
               display != NULL ? display : "???");
        if (display != NULL)
            krb5_free_unparsed_name(ctx, display);
        return 0;
    }
    return 1;
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
pwupdate_precommit_password(kadm5_hook_modinfo *config, krb5_context ctx,
                            krb5_principal principal,
                            const char *password, int pwlen)
{
    krb5_error_code code;
    const char *message;

    if (config->ad_realm == NULL)
        return 0;
    if (password == NULL)
        return 0;
    if (!principal_allowed(config, ctx, principal, 1))
        return 0;
    if (pwupdate_queue_conflict(config, ctx, principal, "ad", "password"))
        goto queue;
    if (config->ad_queue_only)
        goto queue;
    code = pwupdate_ad_change(config, ctx, principal, password, pwlen);
    if (code != 0) {
        message = krb5_get_error_message(ctx, code);
        syslog(LOG_INFO, "krb5-sync: AD password change failed, queuing: %s",
               message);
        krb5_free_error_message(ctx, message);
        goto queue;
    }
    return 0;

queue:
    return pwupdate_queue_write(config, ctx, principal, "ad", "password",
                                password);
}


/*
 * Actions to take after the password is changed in the local database.
 * Currently, there are none.
 */
krb5_error_code
pwupdate_postcommit_password(kadm5_hook_modinfo *config UNUSED,
                             krb5_context ctx UNUSED,
                             krb5_principal principal UNUSED,
                             const char *password UNUSED, int pwlen UNUSED)
{
    return 0;
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
pwupdate_postcommit_status(kadm5_hook_modinfo *config, krb5_context ctx,
                           krb5_principal principal, int enabled)
{
    krb5_error_code code;

    if (config->ad_admin_server == NULL
        || config->ad_keytab == NULL
        || config->ad_principal == NULL
        || config->ad_realm == NULL)
        return 0;
    if (!principal_allowed(config, ctx, principal, 0))
        return 0;
    if (pwupdate_queue_conflict(config, ctx, principal, "ad", "enable"))
        goto queue;
    if (config->ad_queue_only)
        goto queue;
    code = pwupdate_ad_status(config, ctx, principal, enabled);
    if (code != 0)
        goto queue;
    return 0;

queue:
    return pwupdate_queue_write(config, ctx, principal, "ad",
                                enabled ? "enable" : "disable", NULL);
}
