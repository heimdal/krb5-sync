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
int pwupdate_init(krb5_context ctx, void **data);
void pwupdate_close(void *data);
int pwupdate_precommit_password(void *data, krb5_principal principal,
                                const char *password, int pwlen,
				char *errstr, int errstrlen);
int pwupdate_postcommit_password(void *data, krb5_principal principal,
                                 const char *password, int pwlen,
				 char *errstr, int errstrlen);
int pwupdate_postcommit_status(void *data, krb5_principal principal,
                               int enabled, char *errstr, int errstrlen);

/* Password changing. */
int pwupdate_ad_change(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, const char *password,
                       int pwlen, char *errstr, int errstrlen);

/* Account status update. */
int pwupdate_ad_status(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, int enabled, char *errstr,
                       int errstrlen);

/* Instance lookups. */
int pwupdate_instance_exists(krb5_principal principal, const char *instance);

/* Queuing. */
int pwupdate_queue_conflict(struct plugin_config *config, krb5_context ctx,
                            krb5_principal principal, const char *domain,
                            const char *operation);
int pwupdate_queue_write(struct plugin_config *config, krb5_context ctx,
                         krb5_principal principal, const char *domain,
                         const char *operation, const char *password);

/* Error handling. */
void pwupdate_set_error(char *, size_t, krb5_context, krb5_error_code,
                        const char *, ...);

/* Undo default visibility change. */
#pragma GCC visibility pop

END_DECLS

#endif /* !PLUGIN_INTERNAL_H */
