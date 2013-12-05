/*
 * Tests for the MIT Kerberos module API.
 *
 * This just checks that we can call all of the functions and that they return
 * appropriate error messages for a non-existent queue.  We don't try to do
 * any end-to-end testing of the functionality.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dlfcn.h>
#include <errno.h>
#ifdef HAVE_KRB5_KADM5_HOOK_PLUGIN_H
# include <krb5/kadm5_hook_plugin.h>
#endif

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
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
    char *path, *krb5_config, *plugin;
    krb5_error_code code;
    krb5_context ctx;
    krb5_principal princ;
    void *handle = NULL;
    krb5_error_code (*init)(krb5_context, int, int, krb5_plugin_vtable);
    kadm5_hook_vftable_1 vtable;
    kadm5_hook_modinfo *data = NULL;
    kadm5_principal_ent_rec entity;
    const char *message;
    char *wanted;

    /* Set up the default krb5.conf file. */
    path = test_file_path("data/default.conf");
    if (path == NULL)
        bail("cannot find data/default.conf in the test suite");
    basprintf(&krb5_config, "KRB5_CONFIG=%s", path);
    if (putenv(krb5_config) < 0)
        sysbail("cannot set KRB5CCNAME");

    /* Obtain a Kerberos context. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Parse a test principal into a krb5_principal structure. */
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail_krb5(ctx, code, "cannot parse principal test@EXAMPLE.COM");

    /*
     * Load the module.  We assume that the plugin is available as
     * krb5_sync.so in a .libs directory since we don't want to embed
     * Libtool's libtldl just to run a test.  If that's not correct for the
     * local platform, we skip this test.
     */
    plugin = test_file_path("../plugin/.libs/krb5_sync.so");
    if (plugin == NULL)
        skip_all("unknown plugin naming scheme");
    handle = dlopen(plugin, RTLD_NOW);
    if (handle == NULL)
        bail("cannot dlopen %s: %s", plugin, dlerror());
    test_file_path_free(plugin);

    /* Find the entry point function. */
    init = dlsym(handle, "kadm5_hook_krb5_sync_initvt");
    if (init == NULL)
        bail("cannot get kadm5_hook_krb5_sync_initvt symbol: %s", dlerror());

    /* No more skipping, so now we can report a plan. */
    plan(12);

    /* Test for correct results when requesting the wrong API version. */
    code = init(ctx, 2, 0, (krb5_plugin_vtable) &vtable);
    is_int(code, KRB5_PLUGIN_VER_NOTSUPP,
           "Correct status for bad major API version");

    /* Call that function properly to get the vtable. */
    memset(&vtable, 0, sizeof(vtable));
    code = init(ctx, 1, 0, (krb5_plugin_vtable) &vtable);
    if (code != 0)
        bail_krb5(ctx, code, "cannot obtain module vtable");

    /* Check that all of the expected vtable entries are present. */
    if (vtable.init == NULL || vtable.fini == NULL || vtable.chpass == NULL
        || vtable.create == NULL || vtable.modify == NULL)
        bail("missing function in module vtable");

    /* Verify the metadata. */
    is_string("krb5_sync", vtable.name, "Hook name is correct");

    /*
     * Call the chpass function, which should fail with errors about queuing
     * since the queue doesn't exist.
     */
    basprintf(&wanted, "cannot open lock file queue/.lock: %s",
              strerror(ENOENT));
    is_int(0, vtable.init(ctx, &data), "init");
    ok(data != NULL, "...and data is not NULL");
    code = vtable.chpass(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, princ, false,
                         0, NULL, "test");
    is_int(ENOENT, code, "chpass");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test chpass with a NULL password, which should do nothing. */
    code = vtable.chpass(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, princ, false,
                         0, NULL, NULL);
    is_int(0, code, "chpass with NULL password");

    /*
     * Set up an entry for creating an account.  Everything in the entity is
     * ignored except the principal and attributes, so don't bother to fake
     * much up here.
     */
    memset(&entity, 0, sizeof(entity));
    entity.principal = princ;
    entity.attributes = KRB5_KDB_DISALLOW_ALL_TIX;

    /* Test creation with no queue directory. */
    code = vtable.create(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, &entity, 0, 0,
                         NULL, "test");
    is_int(ENOENT, code, "create");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test disabling with no queue directory. */
    code = vtable.modify(ctx, data, KADM5_HOOK_STAGE_POSTCOMMIT, &entity,
                         KADM5_ATTRIBUTES);
    is_int(ENOENT, code, "modify");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test creation with a NULL password, which should do nothing. */
    code = vtable.create(ctx, data, KADM5_HOOK_STAGE_PRECOMMIT, &entity, 0, 0,
                         NULL, NULL);
    is_int(0, code, "create with NULL password");

    /* Close down the module. */
    vtable.fini(ctx, data);
    free(wanted);

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(path);
    free(krb5_config);
    return 0;
}

#endif /* HAVE_KRB5_KADM5_HOOK_PLUGIN_H */
