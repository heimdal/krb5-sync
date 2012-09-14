/*
 * Tests for queuing behavior in the krb5-sync plugin.
 *
 * It's difficult to test actions that make actual LDAP or set_password calls,
 * since one then needs an Active Directory test environment to point at.  But
 * we can test all plugin behavior that involves queuing, by forcing changes
 * to queue.
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

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include <plugin/internal.h>
#include <tests/tap/basic.h>
#include <tests/tap/string.h>


int
main(void)
{
    char *tmpdir, *krb5conf, *env, *queue;
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    void *data;
    int fd;
    char errstr[BUFSIZ], buffer[BUFSIZ];
    time_t now, try;
    struct tm *date;
    FILE *file;

    tmpdir = test_tmpdir();
    if (chdir(tmpdir) < 0)
        sysbail("cannot cd to %s", tmpdir);
    krb5conf = test_file_path("data/krb5.conf");
    if (mkdir("queue", 0777) < 0)
        sysbail("cannot mkdir queue");
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

    plan(10);

    /* Test init. */
    is_int(0, pwupdate_init(ctx, &data), "pwupdate_init succeeds");
    ok(data != NULL, "...and data is non-NULL");

    /* Block processing for our test user and then test password change. */
    fd = open("queue/test-ad-password-19700101T000000Z", O_CREAT | O_WRONLY,
              0666);
    if (fd < 0)
        sysbail("cannot create fake queue file");
    close(fd);
    errstr[0] = '\0';
    code = pwupdate_precommit_password(data, princ, "foobar", strlen("foobar"),
                                       errstr, sizeof(errstr));
    is_int(0, code, "pwupdate_precommit_password succeeds");
    is_int(0, access("queue/.lock", F_OK), "...lock file now exists");
    is_string("", errstr, "...and there is no error");
    queue = NULL;
    now = time(NULL);
    for (try = now - 1; try <= now; try++) {
        date = gmtime(&try);
        basprintf(&queue,
                  "queue/test-ad-password-%04d%02d%02dT%02d%02d%02dZ-00",
                  date->tm_year + 1900, date->tm_mon + 1, date->tm_mday,
                  date->tm_hour, date->tm_min, date->tm_sec);
        if (access(queue, F_OK) == 0)
            break;
        free(queue);
        queue = NULL;
    }
    ok(queue != NULL, "...password change was queued");
    if (queue == NULL)
        ok_block(4, false, "No queued change to check");
    else {
        file = fopen(queue, "r");
        if (file == NULL)
            sysbail("cannot open %s", queue);
        if (fgets(buffer, sizeof(buffer), file) == NULL)
            buffer[0] = '\0';
        is_string("test\n", buffer, "...queued user is correct");
        if (fgets(buffer, sizeof(buffer), file) == NULL)
            buffer[0] = '\0';
        is_string("ad\n", buffer, "...queued domain is correct");
        if (fgets(buffer, sizeof(buffer), file) == NULL)
            buffer[0] = '\0';
        is_string("password\n", buffer, "...queued operation is correct");
        if (fgets(buffer, sizeof(buffer), file) == NULL)
            buffer[0] = '\0';
        is_string("foobar\n", buffer, "...queued password is correct");
        fclose(file);
    }
    free(queue);

    /* Shut down the plugin. */
    pwupdate_close(data);

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    if (system("rm -r queue") != 0)
        bail("cannot remove queue");
    if (chdir("..") < 0)
        sysbail("cannot chdir to parent directory");
    test_file_path_free(krb5conf);
    test_tmpdir_free(tmpdir);
    free(env);
    return 0;
}
