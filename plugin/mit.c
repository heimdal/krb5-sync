/*
 * MIT kadm5_hook shared module API.
 *
 * This is the glue required to connect an MIT Kerberos kadmin hook module to
 * the API for the krb5-sync module.  It is based on the kadm5_hook interface
 * released with MIT Kerberos 1.9, which was based on a preliminary proposal
 * for the Heimdal hook API.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Contributions by Sam Hartman <hartmans@painless-security.com>
 * Copyright 2010, 2011, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2010 The Massachusetts Institute of Technology
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#ifdef HAVE_KRB5_KADM5_HOOK_PLUGIN_H
# include <krb5/kadm5_hook_plugin.h>
#endif

#include <plugin/internal.h>
#include <util/macros.h>

/*
 * Skip this entire file if the relevant MIT Kerberos header isn't available,
 * since without that header we don't have the data types that we need.
 */
#ifdef HAVE_KRB5_KADM5_HOOK_PLUGIN_H

/*
 * The public function that the MIT kadm5 library looks for.  It contains the
 * module name, so it can't be prototyped by the MIT headers.
 */
krb5_error_code kadm5_hook_krb5_sync_initvt(krb5_context, int, int,
                                            krb5_plugin_vtable);


/*
 * Initialize the plugin.  Calls the pwupdate_init() function and returns the
 * resulting data object.
 */
static kadm5_ret_t
init(krb5_context ctx, kadm5_hook_modinfo **data)
{
    return pwupdate_init((struct plugin_config **) data, ctx);
}


/*
 * Shut down the plugin, freeing any internal resources.
 */
static void
fini(krb5_context ctx UNUSED, kadm5_hook_modinfo *data)
{
    pwupdate_close((struct plugin_config *) data);
}


/*
 * Handle a password change.
 */
static kadm5_ret_t
chpass(krb5_context ctx, kadm5_hook_modinfo *data, int stage,
       krb5_principal princ, krb5_boolean keepold UNUSED,
       int n_ks_tuple UNUSED, krb5_key_salt_tuple *ks_tuple UNUSED,
       const char *password)
{
    size_t length;
    krb5_error_code code = 0;

    /*
     * If password is NULL, we have a new key set but no password (meaning
     * this is an operation such as addprinc -randkey).  We can't do anything
     * without a password, so ignore these cases.
     */
    if (password == NULL)
        return 0;

    /* Dispatch to the appropriate function. */
    length = strlen(password);
    if (stage == KADM5_HOOK_STAGE_PRECOMMIT)
        code = pwupdate_precommit_password((struct plugin_config *) data,
                                           ctx, princ, password, length);
    else if (stage == KADM5_HOOK_STAGE_POSTCOMMIT)
        code = pwupdate_postcommit_password((struct plugin_config *) data,
                                            ctx, princ, password, length);
    return code;
}


/*
 * Handle a principal creation.
 *
 * We only care about synchronizing the password, so we just call the same
 * hooks as we did for a password change.
 */
static kadm5_ret_t
create(krb5_context ctx, kadm5_hook_modinfo *data, int stage,
       kadm5_principal_ent_t entry, long mask UNUSED, int n_ks_tuple UNUSED,
       krb5_key_salt_tuple *ks_tuple UNUSED, const char *password)
{
    return chpass(ctx, data, stage, entry->principal, false, n_ks_tuple,
                  ks_tuple, password);
}


/*
 * Handle a principal modification.
 *
 * We only care about changes to the DISALLOW_ALL_TIX flag, and we only
 * support status postcommit.  Check whether that's what's being changed and
 * call the appropriate hook.
 */
static kadm5_ret_t
modify(krb5_context ctx, kadm5_hook_modinfo *data, int stage,
       kadm5_principal_ent_t entry, long mask)
{
    int enabled;

    if (mask & KADM5_ATTRIBUTES && stage == KADM5_HOOK_STAGE_POSTCOMMIT) {
        enabled = !(entry->attributes & KRB5_KDB_DISALLOW_ALL_TIX);
        return pwupdate_postcommit_status((struct plugin_config *) data,
                                          ctx, entry->principal, enabled);
    }
    return 0;
}


/*
 * The public interface called by the kadmin hook code in MIT Kerberos.
 */
krb5_error_code
kadm5_hook_krb5_sync_initvt(krb5_context ctx UNUSED, int maj_ver,
                            int min_ver UNUSED, krb5_plugin_vtable vtable)
{
    kadm5_hook_vftable_1 *vt = (kadm5_hook_vftable_1 *) vtable;
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt->name = "krb5_sync";
    vt->init = init;
    vt->fini = fini;
    vt->chpass = chpass;
    vt->create = create;
    vt->modify = modify;
    return 0;
}

#endif /* HAVE_KRB5_KADM5_HOOK_PLUGIN_H */
