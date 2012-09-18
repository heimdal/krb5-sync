/*
 * Tests for the MIT Kerberos module API.
 *
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dlfcn.h>
#include <errno.h>
#include <kadm5/admin.h>
#ifdef HAVE_KADM5_KADM5_ERR_H
# include <kadm5/kadm5_err.h>
#endif
#ifdef HAVE_KRB5_KADM5_HOOK_PLUGIN_H
# include <krb5/kadm5_hook_plugin.h>
#endif

#include <tests/tap/basic.h>
#include <tests/tap/string.h>


#ifndef HAVE_KRB5_KADM5_HOOK_PLUGIN_H

int
main(void)
{
    skip_all("not built with MIT Kerberos support");
}

#else

int
main(void)
{
    char *krb5conf, *env, *plugin;
    krb5_error_code code;
    krb5_context ctx;
    krb5_principal princ;
    void *handle = NULL;
    krb5_error_code (*callback)(krb5_context, int, int, krb5_plugin_vtable);
    kadm5_hook_vftable_1 hook;
    kadm5_hook_modinfo *data = NULL;
    kadm5_principal_ent_rec entity;

    krb5conf = test_file_path("data/krb5.conf");
    if (krb5conf == NULL)
        bail("cannot find tests/data/krb5.conf");
    basprintf(&env, "KRB5_CONFIG=%s", krb5conf);
    if (putenv(env) < 0)
        sysbail("cannot set KRB5CCNAME");
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("cannot create Kerberos context (%d)", (int) code);
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail("cannot parse principal: %s", krb5_get_error_message(ctx, code));

    /*
     * We assume that the plugin is available as:
     *
     *     BUILD/../plugin/.libs/krb5_sync.so
     *
     * since we don't want to embed Libtool's libtldl just to run a test.  If
     * that's not correct for the local platform, we skip this test.
     */
    plugin = test_file_path("../plugin/.libs/krb5_sync.so");
    if (plugin == NULL)
        skip_all("unknown plugin naming scheme");

    plan(14);

    /* Load the module and find the correct symbol. */
    handle = dlopen(plugin, RTLD_NOW);
    if (handle == NULL)
        diag("dlopen of %s failed: %s", plugin, dlerror());
    ok(handle != NULL, "dlopen succeeds");
    if (handle == NULL)
        ok(false, "dlsym succeeds");
    else {
        callback = dlsym(handle, "kadm5_hook_krb5_sync_initvt");
        ok(callback != NULL, "dlsym succeeds");
    }

    /* Call the callback function and get the vtable. */
    memset(&hook, 0, sizeof(hook));
    if (handle == NULL || callback == NULL)
        ok(false, "callback succeeds");
    else {
        code = callback(ctx, 1, 0, (krb5_plugin_vtable) &hook);
        if (code != 0)
            diag("kadm5_hook_krb5_sync_initvt failed: %s",
                 krb5_get_error_message(ctx, code));
        ok(code == 0, "kadm5_hook_krb5_sync_initvt succeeds");
    }

    /* Check metadata. */
    is_string("krb5_sync", hook.name, "Hook name is correct");

    /*
     * Call the functions, all of which should fail with errors about queuing
     * since the queue doesn't exist.  This verifies that the symbols are all
     * there and that the arguments are basically correct.
     */
    if (hook.name == NULL)
        ok_block(8, false, "No vtable");
    else {
        is_int(0, hook.init(ctx, &data), "init");
        ok(data != NULL, "...and data is not NULL");
        code = hook.chpass(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, princ,
                           false, 0, NULL, "test");
        is_int(KADM5_FAILURE, code, "chpass");
        is_string("cannot synchronize password: queueing AD password change"
                  " failed", krb5_get_error_message(ctx, code),
                  "...with correct error message");

        /* Test chpass with a NULL password. */
        code = hook.chpass(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, princ,
                           false, 0, NULL, NULL);
        is_int(0, code, "chpass with NULL password");

        /*
         * Everything in the entity is ignored except the principal and
         * attributes, so don't bother to fake much up here.
         */
        memset(&entity, 0, sizeof(entity));
        entity.principal = princ;
        entity.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
        code = hook.create(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, &entity,
                           0, 0, NULL, "test");
        is_int(KADM5_FAILURE, code, "create");
        is_string("cannot synchronize password: queueing AD password change"
                  " failed", krb5_get_error_message(ctx, code),
                  "...with correct error message");
        code = hook.modify(ctx, data, KADM5_HOOK_STAGE_POSTCOMMIT, &entity,
                           KADM5_ATTRIBUTES);
        is_int(KADM5_FAILURE, code, "modify");
        is_string("cannot synchronize status: queueing AD status change"
                  " failed", krb5_get_error_message(ctx, code),
                  "...with correct error message");

        /* Test create with a NULL password. */
        code = hook.create(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, &entity, 0,
                           0, NULL, NULL);
        is_int(0, code, "create");

        /* Close down the module. */
        hook.fini(ctx, data);
    }

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(krb5conf);
    free(env);
    return 0;
}

#endif /* HAVE_KRB5_KADM5_HOOK_PLUGIN_H */
