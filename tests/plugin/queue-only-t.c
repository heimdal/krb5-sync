/*
 * Tests for forced queuing in the krb5-sync plugin.
 *
 * Disable immediate changes and force queuing, and test that this works
 * correctly.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <errno.h>
#include <sys/stat.h>

#include <plugin/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/kerberos.h>
#include <tests/tap/process.h>
#include <tests/tap/string.h>
#include <tests/tap/sync.h>


int
main(void)
{
    char *path, *tmpdir, *make_conf, *krb5_config;
    const char *setup_argv[6];
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    kadm5_hook_modinfo *config;

    /* Define the plan. */
    plan(23);

    /* Set up a temporary directory and queue relative to it. */
    path = test_file_path("data/default.conf");
    tmpdir = test_tmpdir();
    if (chdir(tmpdir) < 0)
        sysbail("cannot cd to %s", tmpdir);
    if (mkdir("queue", 0777) < 0)
        sysbail("cannot mkdir queue");

    /* Set up our krb5.conf with ad_queue_only set. */
    make_conf = test_file_path("data/make-krb5-conf");
    setup_argv[0] = make_conf;
    if (setup_argv[0] == NULL)
        bail("cannot find data/make-krb5-conf in the test suite");
    setup_argv[1] = path;
    setup_argv[2] = tmpdir;
    setup_argv[3] = "ad_queue_only";
    setup_argv[4] = "true";
    setup_argv[5] = NULL;
    run_setup(setup_argv);
    test_file_path_free(make_conf);
    test_file_path_free(path);

    /* Point KRB5_CONFIG at the newly-generated krb5.conf file. */
    basprintf(&krb5_config, "KRB5_CONFIG=%s/krb5.conf", tmpdir);
    if (putenv(krb5_config) < 0)
        sysbail("cannot set KRB5_CONFIG in the environment");

    /* Obtain a new Kerberos context with that krb5.conf file. */
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail_krb5(ctx, code, "cannot initialize Kerberos context");

    /* Test init. */
    is_int(0, sync_init(ctx, &config), "sync_init succeeds");
    ok(config != NULL, "...and config is non-NULL");

    /* Create a password change and be sure it's queued. */
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail_krb5(ctx, code, "cannot parse principal test@EXAMPLE.COM");
    code = sync_chpass(config, ctx, princ, "foobar");
    is_int(0, code, "sync_chpass succeeds");
    sync_queue_check_password("queue", "test", "foobar");

    /* Test queuing of enable. */
    code = sync_status(config, ctx, princ, true);
    is_int(0, code, "sync_status enable succeeds");
    sync_queue_check_enable("queue", "test", true);

    /* Test queuing of disable. */
    code = sync_status(config, ctx, princ, false);
    is_int(0, code, "sync_status disable succeeds");
    sync_queue_check_enable("queue", "test", false);

    /* Unwind the queue and be sure all the right files exist. */
    ok(unlink("queue/.lock") == 0, "Lock file still exists");
    ok(rmdir("queue") == 0, "No other files in queue directory");

    /* Shut down the plugin. */
    sync_close(ctx, config);

    /* Manually clean up after the results of make-krb5-conf. */
    basprintf(&path, "%s/krb5.conf", tmpdir);
    unlink(path);
    free(path);
    if (chdir("..") < 0)
        sysbail("cannot chdir to parent directory");
    test_tmpdir_free(tmpdir);

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    putenv((char *) "KRB5_CONFIG=");
    free(krb5_config);
    return 0;
}
