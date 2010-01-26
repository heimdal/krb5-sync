/*
 * Internal prototypes and structures for the kadmind password update plugin.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Based on code developed by Derrick Brashear and Ken Hornstein of Sine
 * Nomine Associates, on behalf of Stanford University.
 * Copyright 2006, 2007 Board of Trustees, Leland Stanford Jr. University
 * See LICENSE for licensing terms.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include "config.h"
#include <krb5.h>
#include <sys/types.h>

/* Used for unused parameters to silence gcc warnings. */
#define UNUSED  __attribute__((__unused__))

/*
 * Local configuration information for the module.  This contains all the
 * parameters that are read from the krb5-sync sub-section of the appdefaults
 * section when the module is initialized.  This structure is passed as an
 * opaque pointer back to the caller, which is then expected to pass it in as
 * the first argument to the other calls.
 */
struct plugin_config {
    char *afs_srvtab;
    char *afs_principal;
    char *afs_realm;
    char *afs_instances;
    char *ad_keytab;
    char *ad_principal;
    char *ad_realm;
    char *ad_admin_server;
    char *ad_ldap_base;
    char *ad_instances;
    char *queue_dir;
};

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
#ifdef HAVE_AFS
int pwupdate_afs_change(struct plugin_config *config, krb5_context ctx,
                        krb5_principal principal, const char *password,
                        int pwlen, char *errstr, int errstrlen);
#endif

/* Account status update. */
int pwupdate_ad_status(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, int enabled, char *errstr,
                       int errstrlen);

/* Queuing. */
int pwupdate_queue_conflict(struct plugin_config *config, krb5_context ctx,
                            krb5_principal principal, const char *domain,
                            const char *operation);
int pwupdate_queue_write(struct plugin_config *config, krb5_context ctx,
                         krb5_principal principal, const char *domain,
                         const char *operation, const char *password);

/* Shutdown. */
#ifdef HAVE_AFS
void pwupdate_afs_close(void);
#endif

/* Error handling. */
void pwupdate_set_error(char *, size_t, krb5_context, krb5_error_code,
                        const char *, ...);

#endif /* !INTERNAL_H */
