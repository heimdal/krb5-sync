/*
 * Heimdal shared module API.
 *
 * This is the glue required to connect a Heimdal kadmin hook module to the
 * API for the krb5-sync module.  It is based on a preliminary proposal for
 * the Heimdal hook API, so the interface exposed here may change in the
 * future.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <errno.h>
#include <kadm5/admin.h>
#include <kadm5/kadm5_err.h>
#include <krb5.h>

#include <plugin/internal.h>
#include <util/macros.h>

#define KADM5_HOOK_VERSION_V0 0

typedef struct kadm5_hook {
    const char *name;
    int version;
    const char *vendor;

    krb5_error_code (*init)(krb5_context, void **);
    void (*fini)(krb5_context, void *);

    krb5_error_code (*chpass)(krb5_context, void *, krb5_principal,
                              const char *);
    krb5_error_code (*create)(krb5_context, void *,
                              kadm5_principal_ent_t, uint32_t mask,
                              const char *password);
    krb5_error_code (*modify)(krb5_context, void *,
                              kadm5_principal_ent_t, uint32_t mask);
} kadm5_hook;


/*
 * Initialize the plugin.  Calls the pwupdate_init() function and returns the
 * resulting data object.
 */
static krb5_error_code
init(krb5_context ctx, void **data)
{
    krb5_error_code code = 0;

    if (pwupdate_init(ctx, data) != 0)
        code = errno;
    return code;
}


/*
 * Shut down the object, freeing any internal resources.
 */
static void
fini(krb5_context ctx UNUSED, void *data)
{
    pwupdate_close(data);
}


/*
 * Handle a password change.
 *
 * We're actually called after the password change is complete, so we should
 * only call the postcommit_password hook, but the precommit hook does what we
 * want.  This needs to be cleaned up later.
 */
static krb5_error_code
chpass(krb5_context ctx, void *data, krb5_principal princ,
       const char *password)
{
    char error[BUFSIZ];
    size_t length;
    int status;

    length = strlen(password);
    status = pwupdate_precommit_password(data, princ, password, length,
                                         error, sizeof(error));
    if (status == 0)
        status = pwupdate_postcommit_password(data, princ, password, length,
                                              error, sizeof(error));
    if (status == 0)
        return 0;
    else {
        krb5_set_error_message(ctx, KADM5_FAILURE,
                               "cannot synchronize password: %s", error);
        return KADM5_FAILURE;
    }
}


/*
 * Handle a principal creation.
 *
 * We only care about synchronizing the password, so we just call the same
 * hooks as we did for a password change.
 */
static krb5_error_code
create(krb5_context ctx, void *data, kadm5_principal_ent_t entry,
       uint32_t mask UNUSED, const char *password)
{
    char error[BUFSIZ];
    size_t length;
    int status;

    length = strlen(password);
    status = pwupdate_precommit_password(data, entry->principal, password,
                                         length, error, sizeof(error));
    if (status == 0)
        status = pwupdate_postcommit_password(data, entry->principal, password,
                                              length, error, sizeof(error));
    if (status == 0)
        return 0;
    else {
        krb5_set_error_message(ctx, KADM5_FAILURE,
                               "cannot synchronize password: %s", error);
        return KADM5_FAILURE;
    }
}


/*
 * Handle a principal modification.
 *
 * We only care about changes to the DISALLOW_ALL_TIX flag.  Check whether
 * that's what's being changed and call the appropriate hook.
 */
static krb5_error_code
modify(krb5_context ctx, void *data, kadm5_principal_ent_t entry,
       uint32_t mask)
{
    char error[BUFSIZ];
    int enabled, status;

    if (mask & KADM5_ATTRIBUTES) {
        enabled = !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX);
        status = pwupdate_postcommit_status(data, entry->principal, enabled,
                                            error, sizeof(error));
        if (status == 0)
            return 0;
        else {
            krb5_set_error_message(ctx, KADM5_FAILURE,
                                   "cannot synchronize status: %s", error);
            return KADM5_FAILURE;
        }
    }
    return 0;
}


/* The public symbol that Heimdal looks for. */
struct kadm5_hook kadm5_hook_v0 = {
    "krb5-sync",
    KADM5_HOOK_VERSION_V0,
    "Russ Allbery",
    init,
    fini,
    chpass,
    create,
    modify
};
