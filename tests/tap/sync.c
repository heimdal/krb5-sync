/*
 * Utility functions for krb5-sync testing.
 *
 * Some additional test functions used by more than one program in the
 * krb5-sync test suite.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/system.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include <tests/tap/basic.h>
#include <tests/tap/string.h>
#include <tests/tap/sync.h>


/*
 * Format the user for queue file naming.  This just replaces all slashes with
 * periods and returns the new user as a newly-allocated string.
 */
static char *
munge_user(const char *user)
{
    char *munged_user, *p;

    munged_user = bstrdup(user);
    for (p = munged_user; *p != '\0'; p++)
        if (*p == '/')
            *p = '.';
    return munged_user;
}


/*
 * Block processing by creating a dummy queue file.  Takes the queue
 * directory, the username (as used for queuing), and the operation to block.
 * Calls bail on failure.
 */
void
sync_queue_block(const char *queue, const char *user, const char *op)
{
    int fd;
    char *file, *munged_user;

    munged_user = munge_user(user);
    basprintf(&file, "%s/%s-ad-%s-19700101T000000Z", queue, munged_user, op);
    free(munged_user);
    fd = open(file, O_CREAT | O_WRONLY, 0666);
    if (fd < 0)
        sysbail("cannot create blocking queue file %s", file);
    close(fd);
    free(file);
}


/*
 * Undo the effects of sync_queue_block and call bail if we can't find the
 * corresponding file.
 */
void
sync_queue_unblock(const char *queue, const char *user, const char *op)
{
    char *file, *munged_user;

    munged_user = munge_user(user);
    basprintf(&file, "%s/%s-ad-%s-19700101T000000Z", queue, munged_user, op);
    free(munged_user);
    if (unlink(file) < 0)
        sysbail("cannot delete blocking queue file %s", file);
    free(file);
}


/*
 * Internal helper function for queue checks.  Takes the queue path, the user,
 * the operation, and (optionally) the password.  Reports results with the
 * normal ok functions and calls bail on system failures.
 */
static void
queue_check(const char *queue, const char *user, const char *op,
            const char *password)
{
    char *path, *wanted, *munged_user;
    const char *path_op;
    time_t now, timestamp;
    struct tm *date;
    struct stat st;
    FILE *file;
    char buffer[BUFSIZ];

    /* Find the queue file.  It should have a nearby timestamp. */
    path = NULL;
    now = time(NULL);
    path_op = (strcmp("disable", op) == 0) ? "enable" : op;
    munged_user = munge_user(user);
    for (timestamp = now - 1; timestamp <= now; timestamp++) {
        date = gmtime(&timestamp);
        basprintf(&path, "%s/%s-ad-%s-%04d%02d%02dT%02d%02d%02dZ-00", queue,
                  munged_user, path_op, date->tm_year + 1900, date->tm_mon + 1,
                  date->tm_mday, date->tm_hour, date->tm_min, date->tm_sec);
        if (access(path, F_OK) == 0)
            break;
        free(path);
        path = NULL;
    }
    free(munged_user);

    /* Check that we found a queued change. */
    ok(path != NULL, "%s for %s was queued", op, user);
    if (path == NULL) {
        if (password == NULL)
            ok_block(4, false, "No queued change to check");
        else
            ok_block(5, false, "No queued change to check");
        free(path);
        return;
    }

    /* Check the file mode. */
    if (stat(path, &st) < 0)
        sysbail("cannot stat %s", path);
    is_int(0600, st.st_mode & 0777, "...mode of queue file is correct");

    /* Open the file and check the data. */
    file = fopen(path, "r");
    if (file == NULL)
        sysbail("cannot open %s", path);
    if (fgets(buffer, sizeof(buffer), file) == NULL)
        buffer[0] = '\0';
    basprintf(&wanted, "%s\n", user);
    is_string(wanted, buffer, "...queued user is correct");
    free(wanted);
    if (fgets(buffer, sizeof(buffer), file) == NULL)
        buffer[0] = '\0';
    is_string("ad\n", buffer, "...queued domain is correct");
    if (fgets(buffer, sizeof(buffer), file) == NULL)
        buffer[0] = '\0';
    basprintf(&wanted, "%s\n", op);
    is_string(wanted, buffer, "...queued operation is correct");
    free(wanted);
    if (password != NULL) {
        if (fgets(buffer, sizeof(buffer), file) == NULL)
            buffer[0] = '\0';
        basprintf(&wanted, "%s\n", password);
        is_string(wanted, buffer, "...queued password is correct");
        free(wanted);
    }
    fclose(file);

    /* Remove the queue file. */
    if (unlink(path) < 0)
        sysbail("cannot delete %s", path);
    free(path);
}


/*
 * Look for an enable or disable change queued in the past second and check
 * that it matches the provided parameters.  Takes the queue, the username,
 * and whether the account should be enabled.  Reports results with the normal
 * ok functions.
 */
void
sync_queue_check_enable(const char *queue, const char *user, bool enable)
{
    queue_check(queue, user, enable ? "enable" : "disable", NULL);
}


/*
 * Look for a password change queued in the past second and check that it
 * matches the provided parameters.  Takes the queue, the username, and the
 * password.  Reports results with the normal ok functions.
 */
void
sync_queue_check_password(const char *queue, const char *user,
                          const char *password)
{
    queue_check(queue, user, "password", password);
}
