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
#include <tests/tap/string.h>
#include <tests/tap/sync.h>


int
main(void)
{
    char *tmpdir, *krb5conf, *env;
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    kadm5_hook_modinfo *config;

    tmpdir = test_tmpdir();
    if (chdir(tmpdir) < 0)
        sysbail("cannot cd to %s", tmpdir);
    krb5conf = test_file_path("data/queue.conf");
    if (krb5conf == NULL)
        bail("cannot find tests/data/queue.conf");
    if (mkdir("queue", 0777) < 0)
        sysbail("cannot mkdir queue");
    basprintf(&env, "KRB5_CONFIG=%s", krb5conf);
    if (putenv(env) < 0)
        sysbail("cannot set KRB5_CONFIG");
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("cannot create Kerberos context (%d)", (int) code);
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail("cannot parse principal: %s", krb5_get_error_message(ctx, code));

    plan(23);

    /* Test init. */
    is_int(0, sync_init(ctx, &config), "sync_init succeeds");
    ok(config != NULL, "...and config is non-NULL");

    /* Create a password change and be sure it's queued. */
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

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(krb5conf);
    if (chdir("..") < 0)
        sysbail("cannot chdir to parent directory");
    test_tmpdir_free(tmpdir);
    free(env);
    return 0;
}
