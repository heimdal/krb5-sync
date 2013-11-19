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
    char errstr[BUFSIZ], buffer[BUFSIZ];
    time_t now, try;
    struct tm *date;
    FILE *file;
    struct stat st;

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

    plan(27);

    /* Test init. */
    is_int(0, pwupdate_init(ctx, &data), "pwupdate_init succeeds");
    ok(data != NULL, "...and data is non-NULL");

    /* Create a password change and be sure it's queued. */
    errstr[0] = '\0';
    code = pwupdate_precommit_password(data, princ, "foobar", strlen("foobar"),
                                       errstr, sizeof(errstr));
    is_int(0, code, "pwupdate_precommit_password succeeds");
    is_string("", errstr, "...and there is no error string");
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
        ok_block(5, false, "No queued change to check");
    else {
        if (stat(queue, &st) < 0)
            sysbail("cannot stat %s", queue);
        is_int(0600, st.st_mode & 0777, "...mode of queue file is correct");
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
    ok(unlink(queue) == 0, "Remove queued password change");
    free(queue);

    /* Test queuing of enable. */
    errstr[0] = '\0';
    code = pwupdate_postcommit_status(data, princ, 1, errstr, sizeof(errstr));
    is_int(0, code, "pwupdate_postcommit_status enable succeeds");
    is_string("", errstr, "...and there is no error");
    queue = NULL;
    now = time(NULL);
    for (try = now - 1; try <= now; try++) {
        date = gmtime(&try);
        basprintf(&queue, "queue/test-ad-enable-%04d%02d%02dT%02d%02d%02dZ-00",
                  date->tm_year + 1900, date->tm_mon + 1, date->tm_mday,
                  date->tm_hour, date->tm_min, date->tm_sec);
        if (access(queue, F_OK) == 0)
            break;
        free(queue);
        queue = NULL;
    }
    ok(queue != NULL, "...enable was queued");
    if (queue == NULL)
        ok_block(3, false, "No queued change to check");
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
        is_string("enable\n", buffer, "...queued operation is correct");
        fclose(file);
    }
    ok(unlink(queue) == 0, "Remove queued enable");

    /* Test queuing of disable. */
        errstr[0] = '\0';
    code = pwupdate_postcommit_status(data, princ, 0, errstr, sizeof(errstr));
    is_int(0, code, "pwupdate_postcommit_status disable succeeds");
    is_string("", errstr, "...and there is no error");
    queue = NULL;
    now = time(NULL);
    for (try = now - 1; try <= now; try++) {
        date = gmtime(&try);
        basprintf(&queue, "queue/test-ad-enable-%04d%02d%02dT%02d%02d%02dZ-00",
                  date->tm_year + 1900, date->tm_mon + 1, date->tm_mday,
                  date->tm_hour, date->tm_min, date->tm_sec);
        if (access(queue, F_OK) == 0)
            break;
        free(queue);
        queue = NULL;
    }
    ok(queue != NULL, "...enable was queued");
    if (queue == NULL)
        ok_block(3, false, "No queued change to check");
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
        is_string("disable\n", buffer, "...queued operation is correct");
        fclose(file);
    }
    ok(unlink(queue) == 0, "Remove queued disable");
    free(queue);

    /* Unwind the queue and be sure all the right files exist. */
    ok(unlink("queue/.lock") == 0, "Lock file still exists");
    ok(rmdir("queue") == 0, "No other files in queue directory");

    /* Shut down the plugin. */
    pwupdate_close(data);

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
