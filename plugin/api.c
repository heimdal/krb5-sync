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
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 * Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
 * See LICENSE for licensing terms.
 */

#include <com_err.h>
#include <errno.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <plugin/internal.h>

/*
 * Load a string option from Kerberos appdefaults, setting the default to NULL
 * if the setting was not found.  This requires an annoying workaround because
 * one cannot specify a default value of NULL.
 */
static void
config_string(krb5_context ctx, const char *opt, char **result)
{
    const char *defval = "";

    krb5_appdefault_string(ctx, "krb5-sync", NULL, opt, defval, result);
    if (*result != NULL && (*result)[0] == '\0') {
        free(*result);
        *result = NULL;
    }
}

/*
 * Initialize the module.  This consists solely of loading our configuration
 * options from krb5.conf into a newly allocated struct stored in the second
 * argument to this function.  Returns 0 on success, non-zero on failre.  This
 * function returns failure only if it could not allocate memory.
 */
int
pwupdate_init(krb5_context ctx, void **data)
{
    struct plugin_config *config;

    config = malloc(sizeof(struct plugin_config));
    if (config == NULL)
        return 1;
#ifdef HAVE_AFS
    config_string(ctx, "afs_srvtab", &config->afs_srvtab);
    config_string(ctx, "afs_principal", &config->afs_principal);
    config_string(ctx, "afs_realm", &config->afs_realm);
    config_string(ctx, "afs_instances", &config->afs_instances);
#else
    config->afs_srvtab = NULL;
    config->afs_principal = NULL;
    config->afs_realm = NULL;
    config->afs_instances = NULL;
#endif
    config_string(ctx, "ad_keytab", &config->ad_keytab);
    config_string(ctx, "ad_principal", &config->ad_principal);
    config_string(ctx, "ad_realm", &config->ad_realm);
    config_string(ctx, "ad_admin_server", &config->ad_admin_server);
    config_string(ctx, "ad_ldap_base", &config->ad_ldap_base);
    config_string(ctx, "ad_instances", &config->ad_instances);
    config_string(ctx, "queue_dir", &config->queue_dir);
    *data = config;
    return 0;
}

/*
 * Shut down the module.  This just means freeing our configuration struct,
 * since we don't store any other local state.
 */
void
pwupdate_close(void *data)
{
    struct plugin_config *config = data;

    if (config->afs_srvtab != NULL)
        free(config->afs_srvtab);
    if (config->afs_principal != NULL)
        free(config->afs_principal);
    if (config->afs_realm != NULL)
        free(config->afs_realm);
#ifdef HAVE_AFS
    pwupdate_afs_close();
#endif
    if (config->ad_keytab != NULL)
        free(config->ad_keytab);
    if (config->ad_principal != NULL)
        free(config->ad_principal);
    if (config->ad_realm != NULL)
        free(config->ad_realm);
    if (config->ad_admin_server != NULL)
        free(config->ad_admin_server);
    if (config->queue_dir != NULL)
        free(config->queue_dir);
    free(config);
}

/*
 * Create a local Kerberos context and set the error appropriately if this
 * fails.  Return true on success, false otherwise.  Puts the error message in
 * errstr on failure.
 */
static int
create_context(krb5_context *ctx, char *errstr, int errstrlen)
{
    krb5_error_code ret;

    ret = krb5_init_context(ctx);
    if (ret != 0) {
        pwupdate_set_error(errstr, errstrlen, *ctx, ret,
                           "failure initializing Kerberos library");
        return 0;
    }
    return 1;
}

/*
 * Given the list of allowed principals as a space-delimited string and the
 * instance of a principal, returns true if that instance is allowed and false
 * otherwise.
 */
static int
instance_allowed(const char *allowed, const krb5_data *instance)
{
    const char *p, *i, *end;
    int checking, okay;

    if (allowed == NULL || instance == NULL)
        return 0;
    i = instance->data;
    end = i + instance->length;
    checking = 1;
    okay = 0;
    for (p = allowed; *p != '\0'; p++) {
        if (*p == ' ') {
            if (okay && i == end)
                break;
            okay = 0;
            checking = 1;
            i = instance->data;
        } else if (checking && (i == end || *p != *i)) {
            okay = 0;
            checking = 0;
            i = instance->data;
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
 * Check the principal for which we're changing a password.  If it contains a
 * non-null instance, we don't want to propagate the change; we only want to
 * change passwords for regular users.  Returns true if we should proceed,
 * false otherwise.  If we shouldn't proceed, logs a debug-level message to
 * syslog.
 */
static int
principal_allowed(struct plugin_config *config, krb5_context ctx,
                  krb5_principal principal, int ad)
{
    if (krb5_princ_size(ctx, principal) > 1) {
        char *display;
        krb5_error_code ret;
        const krb5_data *instance;

        instance = krb5_princ_component(ctx, principal, 1);
        if (ad && instance_allowed(config->ad_instances, instance))
            return 1;
        else if (!ad && instance_allowed(config->afs_instances, instance))
            return 1;
        ret = krb5_unparse_name(ctx, principal, &display);
        if (ret != 0)
            display = NULL;
        syslog(LOG_DEBUG, "account synchronization skipping principal \"%s\""
               " with non-null instance for %s",
               display != NULL ? display : "???",
               ad ? "Active Directory" : "AFS");
        if (display != NULL)
            free(display);
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
 */
int
pwupdate_precommit_password(void *data, krb5_principal principal,
                            const char *password, int pwlen,
                            char *errstr, int errstrlen)
{
    struct plugin_config *config = data;
    krb5_context ctx;
    int status;

    if (config->ad_realm == NULL)
        return 0;
    if (!create_context(&ctx, errstr, errstrlen))
        return 1;
    if (!principal_allowed(config, ctx, principal, 1))
        return 0;
    if (pwupdate_queue_conflict(config, ctx, principal, "ad", "password"))
        goto queue;
    status = pwupdate_ad_change(config, ctx, principal, password, pwlen,
                                errstr, errstrlen);
    if (status == 3) {
        syslog(LOG_INFO, "pwupdate: AD password change failed, queuing: %s",
               errstr);
        goto queue;
    }
    krb5_free_context(ctx);
    return status;

queue:
    status = pwupdate_queue_write(config, ctx, principal, "ad", "password",
                                  password);
    krb5_free_context(ctx);
    if (status)
        return 0;
    else {
        snprintf(errstr, errstrlen, "queueing AD password change failed");
        return 1;
    }
}

/*
 * Actions to take after the password is changed in the local database.
 *
 * Push the new password to the AFS kaserver if we have the necessary
 * configuration information and return any error it returns, but skip any
 * principals with a non-NULL instance since those are kept separately in each
 * realm.
 *
 * If the change fails or if a password change in AFS were already queued for
 * this user, queue the password change.  Only fail if we can't even do that.
 */
#ifdef HAVE_AFS
int pwupdate_postcommit_password(void *data, krb5_principal principal,
                                 const char *password, int pwlen,
				 char *errstr, int errstrlen)
{
    struct plugin_config *config = data;
    krb5_context ctx;
    int status;

    if (config->afs_realm == NULL
        || config->afs_srvtab == NULL
        || config->afs_principal == NULL)
        return 0;
    if (!create_context(&ctx, errstr, errstrlen))
        return 1;
    if (!principal_allowed(config, ctx, principal, 0))
        return 0;
    if (pwupdate_queue_conflict(config, ctx, principal, "afs", "password"))
        goto queue;
    status = pwupdate_afs_change(config, ctx, principal, password, pwlen,
                                 errstr, errstrlen);
    if (status != 0) {
        syslog(LOG_INFO, "pwupdate: AFS password change failed, queuing: %s",
               errstr);
        goto queue;
    }
    krb5_free_context(ctx);
    return status;

queue:
    status = pwupdate_queue_write(config, ctx, principal, "afs", "password",
                                  password);
    krb5_free_context(ctx);
    if (status)
        return 0;
    else {
        snprintf(errstr, errstrlen, "queueing AFS password change failed");
        return 1;
    }
}
#else /* !HAVE_AFS */
int pwupdate_postcommit_password(void *data UNUSED,
                                 krb5_principal principal UNUSED,
                                 const char *password UNUSED, int pwlen UNUSED,
				 char *errstr UNUSED, int errstrlen UNUSED)
{
    return 0;
}
#endif


/*
 * Actions to take after the account status is changed in the local database.
 *
 * Push the new account status to Active Directory if so configured, but skip
 * principals with non-NULL instances.  Return any error that it returns.
 *
 * If a status change is already queued, or if making the status change fails,
 * queue it for later processing.
 */
int
pwupdate_postcommit_status(void *data, krb5_principal principal, int enabled,
                           char *errstr, int errstrlen)
{
    struct plugin_config *config = data;
    krb5_context ctx;
    int status;

    if (config->ad_admin_server == NULL
        || config->ad_keytab == NULL
        || config->ad_principal == NULL
        || config->ad_realm == NULL)
        return 0;
    if (!create_context(&ctx, errstr, errstrlen))
        return 1;
    if (!principal_allowed(config, ctx, principal, 1))
        return 0;
    if (pwupdate_queue_conflict(config, ctx, principal, "ad", "enable"))
        goto queue;
    status = pwupdate_ad_status(config, ctx, principal, enabled, errstr,
                                errstrlen);
    if (status != 0)
        goto queue;
    krb5_free_context(ctx);
    return status;

queue:
    status = pwupdate_queue_write(config, ctx, principal, "ad",
                                  enabled ? "enable" : "disable", NULL);
    krb5_free_context(ctx);
    if (status)
        return 0;
    else {
        snprintf(errstr, errstrlen, "queueing AD status change failed");
        return 1;
    }
}
