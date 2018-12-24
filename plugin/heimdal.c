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

#define KADM5_HOOK_VERSION_V1 1

enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT,
    KADM5_HOOK_STAGE_POSTCOMMIT
};

typedef struct kadm5_hook_ftable {
    int version;
    krb5_error_code (KRB5_CALLCONV *init)(krb5_context, void **data);
    void (KRB5_CALLCONV *fini)(void *data);

    const char *name;
    const char *vendor;

    /*
     * Hook functions; NULL functions are ignored. code is only valid on
     * post-commit hooks and represents the result of the commit. Post-
     * commit hooks are not called if a pre-commit hook aborted the call.
     */
    krb5_error_code (KRB5_CALLCONV *chpass)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ,
					    uint32_t flags,
					    size_t n_ks_tuple,
					    krb5_key_salt_tuple *ks_tuple,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *create)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask,
					    const char *password);

    krb5_error_code (KRB5_CALLCONV *modify)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    kadm5_principal_ent_t ent,
					    uint32_t mask);

    krb5_error_code (KRB5_CALLCONV *delete)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *randkey)(krb5_context context,
					     void *data,
					     enum kadm5_hook_stage stage,
					     krb5_error_code code,
					     krb5_const_principal princ);

    krb5_error_code (KRB5_CALLCONV *rename)(krb5_context context,
					    void *data,
					    enum kadm5_hook_stage stage,
					    krb5_error_code code,
					    krb5_const_principal source,
					    krb5_const_principal target);

    krb5_error_code (KRB5_CALLCONV *set_keys)(krb5_context context,
					      void *data,
					      enum kadm5_hook_stage stage,
					      krb5_error_code code,
					      krb5_const_principal princ,
					      uint32_t flags,
					      size_t n_ks_tuple,
					      krb5_key_salt_tuple *ks_tuple,
					      size_t n_keys,
					      krb5_keyblock *keyblocks);

    krb5_error_code (KRB5_CALLCONV *prune)(krb5_context context,
					   void *data,
					   enum kadm5_hook_stage stage,
					   krb5_error_code code,
					   krb5_const_principal princ,
					   int kvno);

} kadm5_hook_ftable;

static krb5_error_code
init(krb5_context ctx, void **data);

static void
fini(void *data);

static krb5_error_code
chpass(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       krb5_error_code code, krb5_const_principal princ,
       uint32_t flags, size_t n_ks_tuple, krb5_key_salt_tuple *ks_tuple,
       const char *password);

static krb5_error_code
create(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       krb5_error_code code, kadm5_principal_ent_t entry,
       uint32_t mask, const char *password);

static krb5_error_code
modify(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       krb5_error_code code, kadm5_principal_ent_t entry, uint32_t mask);

static const struct kadm5_hook_ftable kadm5_hook_v1 = {
    KADM5_HOOK_VERSION_V1,
    init,
    fini,
    "krb5-sync",
    "Russ Allbery",
    chpass,
    create,
    modify
};

static uintptr_t
get_instance(const char *libname)
{
    if (strcmp(libname, "kadm5") == 0)
	return kadm5_get_instance(libname);
    else if (strcmp(libname, "krb5") == 0)
	return krb5_get_instance(libname);

    return 0;
}

krb5_error_code
kadm5_hook_plugin_load(krb5_context ctx,
		       krb5_get_instance_func_t *func,
		       size_t *n_hooks,
		       const kadm5_hook_ftable *const **hooks);

/*
 * Initialize the plugin.  Calls the pwupdate_init() function and returns the
 * resulting data object.
 */
krb5_error_code
kadm5_hook_plugin_load(krb5_context ctx,
		       krb5_get_instance_func_t *func,
		       size_t *n_hooks,
		       const kadm5_hook_ftable *const **hooks_p)
{
    static const kadm5_hook_ftable *const hooks[] = {
	&kadm5_hook_v1
    };

    *func = get_instance;
    *n_hooks = sizeof(hooks) / sizeof(hooks[0]);
    *hooks_p = hooks;

    return 0;
}

static krb5_context hook_krb5_ctx;

static krb5_error_code
init(krb5_context ctx, void **data)
{
    hook_krb5_ctx = ctx;

    return sync_init(ctx, (kadm5_hook_modinfo **) data);
}

/*
 * Shut down the object, freeing any internal resources.
 */
static void
fini(void *data)
{
    sync_close(hook_krb5_ctx, data);
    hook_krb5_ctx = NULL;
}

/*
 * Handle a password change.
 */
static krb5_error_code
chpass(krb5_context ctx, void *data, enum kadm5_hook_stage stage,
       krb5_error_code code UNUSED, krb5_const_principal princ,
       uint32_t flags UNUSED,
       size_t n_ks_tuple UNUSED, krb5_key_salt_tuple *ks_tuple UNUSED,
       const char *password)
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
        return sync_chpass(data, ctx, (krb5_principal)princ, password);
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
       krb5_error_code code, kadm5_principal_ent_t entry,
       uint32_t mask UNUSED, const char *password)
{
    return chpass(ctx, data, stage, code, entry->principal,
		  0, 0, NULL, password);
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
       krb5_error_code code, kadm5_principal_ent_t entry, uint32_t mask)
{
    bool enabled;

    if (mask & KADM5_ATTRIBUTES &&
	code == 0 && stage == KADM5_HOOK_STAGE_POSTCOMMIT) {
        enabled = !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX);
        return sync_status(data, ctx, entry->principal, enabled);
    }
    return 0;
}
