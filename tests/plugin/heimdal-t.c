/*
 * Tests for the Heimdal module API.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
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

#include <tests/tap/basic.h>
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
    char *krb5conf, *env, *plugin;
    krb5_error_code code;
    krb5_context ctx;
    krb5_principal princ;
    void *handle = NULL;
    void *config = NULL;
    struct kadm5_hook *hook = NULL;
    kadm5_principal_ent_rec entity;
    const char *message;
    char *wanted;

    krb5conf = test_file_path("data/default.conf");
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

    plan(15);

    /* Load the module and find the correct symbol. */
    handle = dlopen(plugin, RTLD_NOW);
    if (handle == NULL)
        diag("dlopen of %s failed: %s", plugin, dlerror());
    ok(handle != NULL, "dlopen succeeds");
    if (handle == NULL)
        ok(false, "dlsym succeeds");
    else {
        hook = dlsym(handle, "kadm5_hook_v0");
        ok(hook != NULL, "dlsym succeeds");
    }

    /* Check metadata. */
    if (hook == NULL)
        ok_block(3, false, "No symbol in plugin");
    else {
        is_string("krb5-sync", hook->name, "Correct name");
        is_int(KADM5_HOOK_VERSION_V0, hook->version, "Correct version");
        is_string("Russ Allbery", hook->vendor, "Correct vendor");
    }

    /*
     * Call the functions, all of which should fail with errors about queuing
     * since the queue doesn't exist.  This verifies that the symbols are all
     * there and that the arguments are basically correct.
     */
    if (hook == NULL)
        ok_block(8, false, "No symbol in plugin");
    else {
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

        /* Test chpass with a NULL password. */
        code = hook->chpass(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, princ,
                            NULL);
        is_int(0, code, "chpass with NULL password");

        /*
         * Everything in the entity is ignored except the principal and
         * attributes, so don't bother to fake much up here.
         */
        memset(&entity, 0, sizeof(entity));
        entity.principal = princ;
        entity.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
        code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, &entity,
                            0, "test");
        is_int(ENOENT, code, "create");
        message = krb5_get_error_message(ctx, code);
        is_string(wanted, message, "...with correct error message");
        krb5_free_error_message(ctx, message);
        code = hook->modify(ctx, config, KADM5_HOOK_STAGE_POSTCOMMIT, &entity,
                            KADM5_ATTRIBUTES);
        is_int(ENOENT, code, "modify");
        message = krb5_get_error_message(ctx, code);
        is_string(wanted, message, "...with correct error message");
        krb5_free_error_message(ctx, message);

        /* Test create with a NULL password. */
        code = hook->create(ctx, config, KADM5_HOOK_STAGE_PRECOMMIT, &entity,
                            0, NULL);
        is_int(0, code, "create with NULL password");

        /* Close down the module. */
        hook->fini(ctx, config);
        free(wanted);
    }

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(krb5conf);
    free(env);
    return 0;
}
