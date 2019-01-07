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
#define KADM5_HOOK_VERSION_V1 1

enum kadm5_hook_stage {
    KADM5_HOOK_STAGE_PRECOMMIT  = 0,
    KADM5_HOOK_STAGE_POSTCOMMIT = 1
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

typedef krb5_error_code
(KRB5_CALLCONV *kadm5_hook_plugin_load_t)(krb5_context context,
					  krb5_get_instance_func_t *func,
					  size_t *n_hooks,
					  const kadm5_hook_ftable *const **hooks);

int
main(int argc, char *argv[])
{
    char *path, *krb5_config, *plugin;
    krb5_error_code code;
    krb5_context ctx;
    krb5_principal princ;
    void *handle = NULL;
    void *config = NULL;
    size_t n_hooks = 0;
    const struct kadm5_hook_ftable *const *hooks = NULL;
    const struct kadm5_hook_ftable *hook;
    kadm5_principal_ent_rec entity;
    const char *message;
    krb5_get_instance_func_t get_instance = NULL;
    char *wanted;
    kadm5_hook_plugin_load_t hook_load;

    /* Set up the default krb5.conf file. */
    path = test_file_path("data/krb5.conf");
    if (path == NULL)
        bail("cannot find data/krb5.conf in the test suite");
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
    hook_load = dlsym(handle, "kadm5_hook_plugin_load");
    if (hook_load == NULL)
        bail("cannot get kadm5_hook_plugin_load symbol: %s", dlerror());
    is_int(0, hook_load(ctx, &get_instance, &n_hooks, &hooks), "load");
    is_int((long)get_instance("krb5"), (long)krb5_get_instance("krb5"), "Heimdal version");

    is_int(1, n_hooks, "n_hooks");
    hook = hooks[0];
    is_int(0, hook->init(ctx, &config), "init");

    /* No more skipping, so now we can report a plan. */
    plan(13);

    /* Verify the metadata. */
    is_string("krb5-sync", hook->name, "Module name");
    is_string("Russ Allbery", hook->vendor, "Module vendor");
    is_int(KADM5_HOOK_VERSION_V1, hook->version, "Module version");

    /*
     * Call init and chpass, which should fail with errors about queuing since
     * the queue doesn't exist.
     */
    basprintf(&wanted, "cannot open lock file queue/.lock: %s",
              strerror(ENOENT));
    ok(config != NULL, "...and config is not NULL");
    code = hook->chpass(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, 0, princ,
                        0, 0, NULL, "test");
    is_int(ENOENT, code, "chpass");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test chpass with a NULL password, which should do nothing. */
    code = hook->chpass(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, 0, princ,
			0, 0, NULL, NULL);
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
    code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, 0, &entity, 0,
                        "test");
    is_int(ENOENT, code, "create");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test disabling with no queue directory. */
    code = hook->modify(ctx, config, KADM5_HOOK_STAGE_POSTCOMMIT, 0, &entity,
                        KADM5_ATTRIBUTES);
    is_int(ENOENT, code, "modify");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Test creation with a NULL password, which should do nothing. */
    code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, 0, &entity, 0,
                        NULL);
    is_int(0, code, "create with NULL password");

    /* Close down the module. */
    hook->fini(config);
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
