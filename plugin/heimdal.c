/*
 * Heimdal shared module API.
 *
 * This is the glue required to connect a Heimdal kadmin hook module to the
 * API for the krb5-sync module.  It is based on a preliminary proposal for
 * the Heimdal hook API, so the interface exposed here may change in the
 * future.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>

#include <plugin/internal.h>
#include <util/macros.h>

#define KADM5_HOOK_VERSION_V0 0

enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT,
    KADM5_HOOK_STAGE_POSTCOMMIT
};

typedef struct kadm5_hook {
    const char *name;
    int version;
    const char *vendor;

    krb5_error_code (*init)(krb5_context, void **);
    void (*fini)(krb5_context, void *);

    krb5_error_code (*chpass)(krb5_context, void *, enum kadm5_hook_stage,
                              krb5_principal, const char *);
    krb5_error_code (*create)(krb5_context, void *, enum kadm5_hook_stage,
                              kadm5_principal_ent_t, uint32_t mask,
                              const char *password);
    krb5_error_code (*modify)(krb5_context, void *, enum kadm5_hook_stage,
                              kadm5_principal_ent_t, uint32_t mask);
} kadm5_hook;


/*
 * Initialize the plugin.  Calls the pwupdate_init() function and returns the
 * resulting data object.
 */
static krb5_error_code
init(krb5_context ctx, void **data)
{
    return sync_init(ctx, (kadm5_hook_modinfo **) data);
}


/*
 * Shut down the object, freeing any internal resources.
 */
static void
fini(krb5_context ctx UNUSED, void *data)
{
    sync_close(data);
}


/*
 * Handle a password change.
 */
static krb5_error_code
chpass(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       krb5_principal princ, const char *password)
{
    /*
     * If password is NULL, we have a new key set but no password (meaning
     * this is an operation such as add -r).  We can't do anything without a
     * password, so ignore these cases.
     */
    if (password == NULL)
        return 0;

    /* Dispatch to the appropriate function. */
    if (stage == KADM5_HOOK_STAGE_PRECOMMIT)
        return sync_chpass(data, ctx, princ, password);
    else
        return 0;
}


/*
 * Handle a principal creation.
 *
 * We only care about synchronizing the password, so we just call the same
 * hooks as we did for a password change.
 */
static krb5_error_code
create(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       kadm5_principal_ent_t entry, uint32_t mask UNUSED,
       const char *password)
{
    return chpass(ctx, data, stage, entry->principal, password);
}


/*
 * Handle a principal modification.
 *
 * We only care about changes to the DISALLOW_ALL_TIX flag, and we only
 * support status postcommit.  Check whether that's what's being changed and
 * call the appropriate hook.
 */
static krb5_error_code
modify(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       kadm5_principal_ent_t entry, uint32_t mask)
{
    bool enabled;

    if (mask & KADM5_ATTRIBUTES && stage == KADM5_HOOK_STAGE_POSTCOMMIT) {
        enabled = !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX);
        return sync_status(data, ctx, entry->principal, enabled);
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
