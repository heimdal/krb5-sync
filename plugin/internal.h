/*
 * Internal prototypes and structures for the kadmind password update plugin.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 *     Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007, 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef PLUGIN_INTERNAL_H
#define PLUGIN_INTERNAL_H 1

#include <config.h>
#include <portable/krb5.h>
#include <portable/macros.h>

#include <sys/types.h>

/*
 * Local configuration information for the module.  This contains all the
 * parameters that are read from the krb5-sync sub-section of the appdefaults
 * section when the module is initialized.  This structure is passed as an
 * opaque pointer back to the caller, which is then expected to pass it in as
 * the first argument to the other calls.
 */
struct plugin_config {
    char *ad_keytab;
    char *ad_principal;
    char *ad_realm;
    char *ad_admin_server;
    char *ad_ldap_base;
    char *ad_base_instance;
    char *ad_instances;
    bool ad_queue_only;
    char *queue_dir;
};

BEGIN_DECLS

/* Default to a hidden visibility for all internal functions. */
#pragma GCC visibility push(hidden)

/* General public API. */
krb5_error_code pwupdate_init(struct plugin_config **, krb5_context);
void pwupdate_close(struct plugin_config *);
krb5_error_code pwupdate_precommit_password(struct plugin_config *,
                                            krb5_context, krb5_principal,
                                            const char *password,
                                            int pwlen);
krb5_error_code pwupdate_postcommit_password(struct plugin_config *,
                                             krb5_context, krb5_principal,
                                             const char *password,
                                             int pwlen);
krb5_error_code pwupdate_postcommit_status(struct plugin_config *,
                                           krb5_context, krb5_principal,
                                           int enabled);

/* Password changing. */
krb5_error_code pwupdate_ad_change(struct plugin_config *, krb5_context,
                                   krb5_principal, const char *password,
                                   int pwlen);

/* Account status update. */
krb5_error_code pwupdate_ad_status(struct plugin_config *, krb5_context,
                                   krb5_principal, int enabled);

/* Instance lookups. */
int pwupdate_instance_exists(struct plugin_config *, krb5_context,
                             krb5_principal, const char *instance);

/* Queuing. */
int pwupdate_queue_conflict(struct plugin_config *, krb5_context,
                            krb5_principal, const char *domain,
                            const char *operation);
krb5_error_code pwupdate_queue_write(struct plugin_config *, krb5_context,
                                     krb5_principal, const char *domain,
                                     const char *operation,
                                     const char *password);

/*
 * Obtain configuration settings from krb5.conf.  These are wrappers around
 * the krb5_appdefault_* APIs that handle setting the section name, obtaining
 * the local default realm and using it to find settings, and doing any
 * necessary conversion.
 */
void sync_config_boolean(krb5_context, const char *, bool *)
    __attribute__((__nonnull__));
void sync_config_string(krb5_context, const char *, char **)
    __attribute__((__nonnull__));

/*
 * Store a configuration, generic, or system error in the Kerberos context,
 * appending the strerror results to the message in the _system case and the
 * LDAP error string in the _ldap case.  Returns the error code set.
 */
krb5_error_code sync_error_config(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code sync_error_generic(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));
krb5_error_code sync_error_ldap(krb5_context, int, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 3, 4)));
krb5_error_code sync_error_system(krb5_context, const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 2, 3)));

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PLUGIN_INTERNAL_H */
