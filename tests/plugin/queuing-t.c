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
    char *tmpdir, *krb5conf, *env, *queuepw;
    krb5_context ctx;
    krb5_principal princ;
    krb5_error_code code;
    void *data;
    int fd;
    char errstr[BUFSIZ], buffer[BUFSIZ];
    time_t now, try;
    struct tm *date;
    FILE *file;
    struct stat st;

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

    plan(17);

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
    ok(access("queue/.lock", F_OK) == 0, "...lock file now exists");
    is_string("", errstr, "...and there is no error");
    queuepw = NULL;
    now = time(NULL);
    for (try = now - 1; try <= now; try++) {
        date = gmtime(&try);
        basprintf(&queuepw,
                  "queue/test-ad-password-%04d%02d%02dT%02d%02d%02dZ-00",
                  date->tm_year + 1900, date->tm_mon + 1, date->tm_mday,
                  date->tm_hour, date->tm_min, date->tm_sec);
        if (access(queuepw, F_OK) == 0)
            break;
        free(queuepw);
        queuepw = NULL;
    }
    ok(queuepw != NULL, "...password change was queued");
    if (queuepw == NULL)
        ok_block(5, false, "No queued change to check");
    else {
        if (stat(queuepw, &st) < 0)
            sysbail("cannot stat %s", queuepw);
        is_int(0600, st.st_mode & 0777, "...mode of queue file is correct");
        file = fopen(queuepw, "r");
        if (file == NULL)
            sysbail("cannot open %s", queuepw);
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

    /* pwupdate_postcommit_password should do nothing, silently. */
    code = pwupdate_postcommit_password(data, princ, "foobar",
                                        strlen("foobar"), errstr,
                                        sizeof(errstr));
    is_int(0, code, "pwupdate_precommit_password succeeds");
    is_string("", errstr, "...and there is no error");

    /* Shut down the plugin. */
    pwupdate_close(data);

    /* Unwind the queue and be sure all the right files exist. */
    ok(unlink("queue/test-ad-password-19700101T000000Z") == 0,
       "Sentinel file still exists");
    ok(unlink("queue/.lock") == 0, "Lock file still exists");
    ok(unlink(queuepw) == 0, "Queued password change still exists");
    ok(rmdir("queue") == 0, "No other files in queue directory");
    free(queuepw);

    /* Clean up. */
    krb5_free_principal(ctx, princ);
    krb5_free_context(ctx);
    if (chdir("..") < 0)
        sysbail("cannot chdir to parent directory");
    test_file_path_free(krb5conf);
    test_tmpdir_free(tmpdir);
    free(env);
    return 0;
}
