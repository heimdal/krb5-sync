/*
 * internal.h
 *
 * Internal prototypes and structures for the kadmind password update plugin.
 */

#ifndef INTERNAL_H
#define INTERNAL_H 1

#include <krb5.h>

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
    char *ad_keytab;
    char *ad_principal;
    char *ad_realm;
    char *ad_admin_server;
};

/* General public API. */
int pwupdate_init(krb5_context ctx, void **data);
int pwupdate_precommit_password(void *data, krb5_principal principal,
                                char *password, int pwlen,
				char *errstr, int errstrlen);
int pwupdate_postcommit_password(void *data, krb5_principal principal,
                                 char *password, int pwlen,
				 char *errstr, int errstrlen);
int pwupdate_postcommit_status(void *data, krb5_principal principal,
                               int enabled, char *errstr, int errstrlen);

/* Password changing. */
int pwupdate_ad_change(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, char *password, int pwlen,
                       char *errstr, int errstrlen);
int pwupdate_afs_change(struct plugin_config *config, krb5_context ctx,
                        krb5_principal principal, char *password, int pwlen,
                        char *errstr, int errstrlen);

/* Account status update. */
int pwupdate_ad_status(struct plugin_config *config, krb5_context ctx,
                       krb5_principal principal, int enabled, char *errstr,
                       int errstrlen);

#endif /* !INTERNAL_H */
