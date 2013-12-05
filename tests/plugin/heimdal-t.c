/*
 * Tests for the Heimdal module API.
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

#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/string.h>

/*
 * This is intentionally duplicated from the module so that the test will fail
 * if we change the interface in a way that isn't backward-compatible.
 */
#define KADM5_HOOK_VERSION_V0 0

enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT  = 0,
    KADM5_HOOK_STAGE_POSTCOMMIT = 1
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


int
main(void)
{
    char *path, *krb5_config, *plugin;
    krb5_error_code code;
    krb5_context ctx;
    krb5_principal princ;
    void *handle = NULL;
    void *config = NULL;
    struct kadm5_hook *hook = NULL;
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
     * Load the module.  We assume that the plugin is available as sync.so in
     * a .libs directory since we don't want to embed Libtool's libtldl just
     * to run a test.  If that's not correct for the local platform, we skip
     * this test.
     */
    plugin = test_file_path("../plugin/.libs/sync.so");
    if (plugin == NULL)
        skip_all("unknown plugin naming scheme");
    handle = dlopen(plugin, RTLD_NOW);
    if (handle == NULL)
        bail("cannot dlopen %s: %s", plugin, dlerror());
    test_file_path_free(plugin);

    /* Find the dispatch table and do a basic sanity check. */
    hook = dlsym(handle, "kadm5_hook_v0");
    if (hook == NULL)
        bail("cannot get kadm5_hook_v0 symbol: %s", dlerror());
    if (hook->init == NULL)
        bail("no init function found in module");

    /* No more skipping, so now we can report a plan. */
    plan(13);

    /* Verify the metadata. */
    is_string("krb5-sync", hook->name, "Module name");
    is_string("Russ Allbery", hook->vendor, "Module vendor");
    is_int(KADM5_HOOK_VERSION_V0, hook->version, "Module version");

    /*
     * Call init and chpass, which should fail with errors about queuing since
     * the queue doesn't exist.
     */
    basprintf(&wanted, "cannot open lock file queue/.lock: %s",
              strerror(ENOENT));
    is_int(0, hook->init(ctx, &config), "init");
    ok(config != NULL, "...and config is not NULL");
    code = hook->chpass(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, princ,
                        "test");
    is_int(ENOENT, code, "chpass");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test chpass with a NULL password, which should do nothing. */
    code = hook->chpass(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, princ, NULL);
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
    code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, &entity, 0,
                        "test");
    is_int(ENOENT, code, "create");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test disabling with no queue directory. */
    code = hook->modify(ctx, config, KADM5_HOOK_STAGE_POSTCOMMIT, &entity,
                        KADM5_ATTRIBUTES);
    is_int(ENOENT, code, "modify");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test creation with a NULL password, which should do nothing. */
    code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, &entity, 0,
                        NULL);
    is_int(0, code, "create with NULL password");

    /* Close down the module. */
    hook->fini(ctx, config);
    if (dlclose(handle) != 0)
        bail("cannot close plugin: %s", dlerror());
    free(wanted);

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(path);
    free(krb5_config);
    return 0;
}
