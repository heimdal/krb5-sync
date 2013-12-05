/*
 * Tests for queuing behavior in the krb5-sync plugin.
 *
 * It's difficult to test actions that make actual LDAP or set_password calls,
 * since one then needs an Active Directory test environment to point at.  But
 * we can test all plugin behavior that involves queuing, by forcing changes
 * to queue.
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

#include <errno.h>
#include <sys/stat.h>

#include <plugin/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <tests/tap/sync.h>


int
main(void)
{
    char *tmpdir, *krb5conf, *env, *old_env;
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    kadm5_hook_modinfo *data;
    const char *message;
    char *wanted;

    tmpdir = test_tmpdir();
    if (chdir(tmpdir) < 0)
        sysbail("cannot cd to %s", tmpdir);
    krb5conf = test_file_path("data/default.conf");
    if (krb5conf == NULL)
        bail("cannot find tests/data/krb5.conf");
    if (mkdir("queue", 0777) < 0)
        sysbail("cannot mkdir queue");
    basprintf(&env, "KRB5_CONFIG=%s", krb5conf);
    if (putenv(env) < 0)
        sysbail("cannot set KRB5CCNAME");
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("cannot create Kerberos context (%d)", (int) code);
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail("cannot parse principal: %s", krb5_get_error_message(ctx, code));

    plan(32);

    /* Test init. */
    is_int(0, sync_init(ctx, &data), "pwupdate_init succeeds");
    ok(data != NULL, "...and data is non-NULL");

    /* Block processing for our test user and then test password change. */
    sync_queue_block("queue", "test", "password");
    code = sync_chpass(data, ctx, princ, "foobar");
    is_int(0, code, "pwupdate_precommit_password succeeds");
    ok(access("queue/.lock", F_OK) == 0, "...lock file now exists");
    sync_queue_check_password("queue", "test", "foobar");
    sync_queue_unblock("queue", "test", "password");

    /* Block processing for our test user and then test enable. */
    sync_queue_block("queue", "test", "enable");
    code = sync_status(data, ctx, princ, true);
    is_int(0, code, "sync_status enable succeeds");
    sync_queue_check_enable("queue", "test", true);

    /* Do the same thing for disables, which should still be blocked. */
    code = sync_status(data, ctx, princ, false);
    is_int(0, code, "sync_status disable succeeds");
    sync_queue_check_enable("queue", "test", false);
    sync_queue_unblock("queue", "test", "enable");

    /* Unwind the queue and be sure all the right files exist. */
    ok(unlink("queue/.lock") == 0, "Lock file still exists");
    ok(rmdir("queue") == 0, "No other files in queue directory");

    /* Check failure when there's no queue directory. */
    basprintf(&wanted, "cannot open lock file queue/.lock: %s",
              strerror(ENOENT));
    code = sync_chpass(data, ctx, princ, "foobar");
    is_int(ENOENT, code, "sync_chpass fails with no queue");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);
    code = sync_status(data, ctx, princ, false);
    is_int(ENOENT, code, "sync_status disable fails with no queue");
    message = krb5_get_error_message(ctx, code);
    is_string(wanted, message, "...with correct error message");
    krb5_free_error_message(ctx, message);

    /* Shut down the plugin. */
    sync_close(ctx, data);
    free(wanted);

    /*
     * Change to an empty Kerberos configuration file, and then make sure the
     * plugin does nothing when there's no configuration.
     */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    test_file_path_free(krb5conf);
    krb5conf = test_file_path("data/empty.conf");
    if (krb5conf == NULL)
        bail("cannot find tests/data/empty.conf");
    old_env = env;
    basprintf(&env, "KRB5_CONFIG=%s", krb5conf);
    if (putenv(env) < 0)
        sysbail("cannot set KRB5CCNAME");
    free(old_env);
    code = krb5_init_context(&ctx);
    if (code != 0)
        bail("cannot create Kerberos context (%d)", (int) code);
    code = krb5_parse_name(ctx, "test@EXAMPLE.COM", &princ);
    if (code != 0)
        bail("cannot parse principal: %s", krb5_get_error_message(ctx, code));
    is_int(0, sync_init(ctx, &data), "sync_init succeeds");
    ok(data != NULL, "...and data is non-NULL");
    code = sync_chpass(data, ctx, princ, "foobar");
    is_int(0, code, "sync_chpass succeeds");
    code = sync_status(data, ctx, princ, false);
    is_int(0, code, "sync_status disable succeeds");
    sync_close(ctx, data);

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
