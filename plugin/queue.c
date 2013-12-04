/*
 * Change queuing and queue checking.
 *
 * For some of the changes done by this plugin, we want to queue the change if
 * it failed rather than simply failing the operation.  These functions
 * implement that queuing.  Before making a change, we also need to check
 * whether conflicting changes are already queued, and if so, either queue our
 * operation as well or fail our operation so that correct changes won't be
 * undone.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2010, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <time.h>

#include <plugin/internal.h>

/*
 * Maximum number of queue files we will permit for a given user and action
 * within a given timestamp, and longest string representation of the count.
 */
#define MAX_QUEUE     100
#define MAX_QUEUE_STR "99"

/* Write out a string, checking that all of it was written. */
#define WRITE_CHECK(fd, s)                                              \
    do {                                                                \
        ssize_t result;                                                 \
        result = write((fd), (s), strlen(s));                           \
        if (result < 0 || (size_t) result != strlen(s)) {               \
            code = sync_error_system(ctx, "cannot write queue file");   \
            goto fail;                                                  \
        }                                                               \
    } while (0)


/*
 * Lock the queue directory and stores the file descriptor of the lock in the
 * secon argument.  This must be passed into unlock_queue when the queue
 * should be unlocked.  Returns a Kerberos status code.
 *
 * We have to use flock for compatibility with the Perl krb5-sync-backend
 * script.  Perl makes it very annoying to use fcntl locking on Linux.
 */
static krb5_error_code
lock_queue(kadm5_hook_modinfo *config, krb5_context ctx, int *result)
{
    char *lockpath = NULL;
    int fd = -1;
    krb5_error_code code;

    if (asprintf(&lockpath, "%s/.lock", config->queue_dir) < 0)
        return sync_error_system(ctx, "cannot allocate memory");
    fd = open(lockpath, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        code = sync_error_system(ctx, "cannot open lock file %s", lockpath);
        goto fail;
    }
    if (flock(fd, LOCK_EX) < 0) {
        code = sync_error_system(ctx, "cannot flock lock file %s", lockpath);
        goto fail;
    }
    free(lockpath);
    *result = fd;
    return 0;

fail:
    free(lockpath);
    if (fd >= 0)
        close(fd);
    return code;
}


/*
 * Unlock the queue directory.  Takes the file descriptor of the open lock
 * file, returned by lock_queue.  We assume that this function will never
 * fail.
 */
static void
unlock_queue(int fd)
{
    close(fd);
}


/*
 * Given a Kerberos principal, a context, a domain, and an operation, generate
 * the prefix for queue files as a newly allocated string.  Returns a Kerberos
 * status code.
 */
static krb5_error_code
queue_prefix(krb5_context ctx, krb5_principal principal, const char *domain,
             const char *operation, char **prefix)
{
    char *user = NULL;
    char *p;
    int oerrno;
    krb5_error_code code;

    /* Enable and disable should go into the same queue. */
    if (strcmp(operation, "disable") == 0)
        operation = "enable";
    code = krb5_unparse_name(ctx, principal, &user);
    if (code != 0)
        return code;
    p = strchr(user, '@');
    if (p != NULL)
        *p = '\0';
    while ((p = strchr(user, '/')) != NULL)
        *p = '.';
    if (asprintf(prefix, "%s-%s-%s-", user, domain, operation) < 0) {
        oerrno = errno;
        krb5_free_unparsed_name(ctx, user);
        errno = oerrno;
        return sync_error_system(ctx, "cannot create queue prefix");
    }
    krb5_free_unparsed_name(ctx, user);
    return 0;
}


/*
 * Generate a timestamp from the current date and store it in the argument.
 * Uses the ISO timestamp format.  Returns a Kerberos status code.
 */
static krb5_error_code
queue_timestamp(krb5_context ctx, char **timestamp)
{
    struct tm now;
    time_t seconds;
    int status;

    seconds = time(NULL);
    if (seconds == (time_t) -1)
        return sync_error_system(ctx, "cannot get current time");
    if (gmtime_r(&seconds, &now) == NULL)
        return sync_error_system(ctx, "cannot get broken-down time");
    now.tm_mon++;
    now.tm_year += 1900;
    status = asprintf(timestamp, "%04d%02d%02dT%02d%02d%02dZ", now.tm_year,
                      now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min,
                      now.tm_sec);
    if (status < 0)
        return sync_error_system(ctx, "cannot create timestamp");
    else
        return 0;
}


/*
 * Given a Kerberos context, a principal (assumed to have no instance), a
 * domain (currently always "ad"), and an operation, check whether there are
 * any existing queued actions for that combination, storing the result in the
 * final boolean variable.  Returns a Kerberos status code.
 */
krb5_error_code
sync_queue_conflict(kadm5_hook_modinfo *config, krb5_context ctx,
                    krb5_principal principal, const char *domain,
                    const char *operation, bool *conflict)
{
    int lock = -1;
    char *prefix = NULL;
    DIR *queue = NULL;
    struct dirent *entry;
    krb5_error_code code;

    if (config->queue_dir == NULL)
        return -1;
    code = queue_prefix(ctx, principal, domain, operation, &prefix);
    if (code != 0)
        goto fail;
    code = lock_queue(config, ctx, &lock);
    if (code != 0)
        goto fail;
    queue = opendir(config->queue_dir);
    if (queue == NULL) {
        code = sync_error_system(ctx, "cannot open %s", config->queue_dir);
        goto fail;
    }
    *conflict = false;
    while ((entry = readdir(queue)) != NULL) {
        if (strncmp(prefix, entry->d_name, strlen(prefix)) == 0) {
            *conflict = true;
            break;
        }
    }
    unlock_queue(lock);
    closedir(queue);
    free(prefix);
    return 0;

fail:
    if (lock >= 0)
        unlock_queue(lock);
    if (queue != NULL)
        closedir(queue);
    free(prefix);
    return code;
}


/*
 * Queue an action.  Takes the plugin configuration, the Kerberos context, the
 * principal, the domain, the operation, and a password (which may be NULL for
 * enable and disable).  Returns a Kerberos error code.
 */
krb5_error_code
sync_queue_write(kadm5_hook_modinfo *config, krb5_context ctx,
                 krb5_principal principal, const char *domain,
                 const char *operation, const char *password)
{
    char *prefix = NULL, *timestamp = NULL, *path = NULL, *user = NULL;
    char *p;
    unsigned int i;
    krb5_error_code code;
    int lock = -1, fd = -1;

    if (config->queue_dir == NULL)
        return sync_error_config(ctx, "configuration setting queue_dir"
                                 " missing");
    code = queue_prefix(ctx, principal, domain, operation, &prefix);
    if (code != 0)
        return code;

    /*
     * Lock the queue before the timestamp so that another writer coming up
     * at the same time can't get an earlier timestamp.
     */
    code = lock_queue(config, ctx, &lock);
    if (code != 0)
        goto fail;
    code = queue_timestamp(ctx, &timestamp);
    if (code != 0)
        goto fail;

    /* Find a unique filename for the queue file. */
    for (i = 0; i < MAX_QUEUE; i++) {
        free(path);
        path = NULL;
        code = asprintf(&path, "%s/%s%s-%02d", config->queue_dir, prefix,
                        timestamp, i);
        if (code < 0) {
            code = sync_error_system(ctx, "cannot create queue file name");
            goto fail;
        }
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0)
            break;
    }

    /*
     * Get the username from the principal and chop off the realm, dealing
     * properly with escaped @ characters.
     */
    code = krb5_unparse_name(ctx, principal, &user);
    if (code != 0)
        goto fail;
    for (p = user; *p != '\0'; p++) {
        if (p[0] == '\\' && p[1] != '\0') {
            p++;
        } else if (p[0] == '@') {
            p[0] = '\0';
            break;
        }
    }

    /* Write out the queue data. */
    WRITE_CHECK(fd, user);
    WRITE_CHECK(fd, "\n");
    WRITE_CHECK(fd, domain);
    WRITE_CHECK(fd, "\n");
    WRITE_CHECK(fd, operation);
    WRITE_CHECK(fd, "\n");
    if (password != NULL) {
        WRITE_CHECK(fd, password);
        WRITE_CHECK(fd, "\n");
    }

    /* We're done. */
    close(fd);
    unlock_queue(lock);
    krb5_free_unparsed_name(ctx, user);
    free(prefix);
    free(timestamp);
    free(path);
    return 0;

fail:
    if (fd >= 0) {
        if (path != NULL)
            unlink(path);
        close(fd);
    }
    if (lock >= 0)
        unlock_queue(lock);
    if (user != NULL)
        krb5_free_unparsed_name(ctx, user);
    free(prefix);
    free(timestamp);
    free(path);
    return code;
}
