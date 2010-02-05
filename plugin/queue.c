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
 * Written by Russ Allbery <rra@stanford.edu>
 * Copyright 2006, 2007, 2010 Board of Trustees, Leland Stanford Jr. University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <dirent.h>
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
#define WRITE_CHECK(fd, s)                              \
    do {                                                \
        ssize_t status;                                 \
        status = write((fd), (s), strlen(s));           \
        if (status < 0 || (size_t) status != strlen(s)) \
            goto fail;                                  \
    } while (0)


/*
 * Lock the queue directory.  Returns a file handle to the lock file, which
 * must then be passed into unlock_queue when the queue should be unlocked, or
 * -1 on failure to lock.
 *
 * We have to use flock for compatibility with the Perl krb5-sync-backend
 * script.  Perl makes it very annoying to use fcntl locking on Linux.
 */
static int
lock_queue(struct plugin_config *config)
{
    char *lockpath = NULL;
    int fd = -1;

    if (asprintf(&lockpath, "%s/.lock", config->queue_dir) < 0)
        return -1;
    fd = open(lockpath, O_RDWR | O_CREAT, 0644);
    if (fd < 0)
        goto fail;
    free(lockpath);
    lockpath = NULL;
    if (flock(fd, LOCK_EX) < 0)
        goto fail;
    return fd;

fail:
    if (lockpath != NULL)
        free(lockpath);
    if (fd >= 0)
        close(fd);
    return -1;
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
 * the prefix for queue files as a newly allocated string.  Returns NULL on
 * failure.
 */
static char *
queue_prefix(krb5_context ctx, krb5_principal principal, const char *domain,
             const char *operation)
{
    char *user = NULL, *prefix = NULL;
    char *p;
    krb5_error_code retval;

    /* Enable and disable should go into the same queue. */
    if (strcmp(operation, "disable") == 0)
        operation = "enable";
    retval = krb5_unparse_name(ctx, principal, &user);
    if (retval != 0)
        return NULL;
    p = strchr(user, '@');
    if (p != NULL)
        *p = '\0';
    while ((p = strchr(user, '/')) != NULL)
        *p = '.';
    if (asprintf(&prefix, "%s-%s-%s-", user, domain, operation) < 0) {
        krb5_free_unparsed_name(ctx, user);
        return NULL;
    }
    krb5_free_unparsed_name(ctx, user);
#endif
    return prefix;
}


/*
 * Generate a timestamp from the current date and return it as a newly
 * allocated string, or NULL on failure.  Uses the ISO timestamp format.
 */
static char *
queue_timestamp(void)
{
    struct tm now;
    time_t seconds;
    size_t length;
    char *timestamp;

    seconds = time(NULL);
    if (seconds == (time_t) -1)
        return NULL;
    if (gmtime_r(&seconds, &now) == NULL)
        return NULL;
    now.tm_mon++;
    now.tm_year += 1900;
    length = strlen("YYYYMMDDTHHMMSSZ") + 1;
    timestamp = malloc(length);
    if (timestamp == NULL)
        return NULL;
    snprintf(timestamp, length, "%04d%02d%02dT%02d%02d%02dZ", now.tm_year,
             now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec);
    return timestamp;
}


/*
 * Given a Kerberos context, a principal (assumed to have no instance), a
 * domain (afs or ad), and an operation, check whether there are any existing
 * queued actions for that combination.  Returns 1 if there are, 0 otherwise.
 * On failure, return -1 (still true but distinguished).
 */
int
pwupdate_queue_conflict(struct plugin_config *config, krb5_context ctx,
                        krb5_principal principal, const char *domain,
                        const char *operation)
{
    int lock = -1;
    char *prefix = NULL;
    DIR *queue = NULL;
    struct dirent *entry;
    int found = 0;

    if (config->queue_dir == NULL)
        return -1;
    prefix = queue_prefix(ctx, principal, domain, operation);
    if (prefix == NULL)
        return -1;
    lock = lock_queue(config);
    if (lock < 0)
        goto fail;
    queue = opendir(config->queue_dir);
    if (queue == NULL)
        goto fail;
    while ((entry = readdir(queue)) != NULL) {
        if (strncmp(prefix, entry->d_name, strlen(prefix)) == 0) {
            found = 1;
            break;
        }
    }
    unlock_queue(lock);
    closedir(queue);
    free(prefix);
    return found;

fail:
    if (lock >= 0)
        unlock_queue(lock);
    if (queue != NULL)
        closedir(queue);
    if (prefix != NULL)
        free(prefix);
    return -1;
}


/*
 * Queue an action.  Takes the plugin configuration, the Kerberos context, the
 * principal, the domain, the operation, and a password (which may be NULL for
 * enable and disable).  Returns true on success, false on failure.
 */
int
pwupdate_queue_write(struct plugin_config *config, krb5_context ctx,
                     krb5_principal principal, const char *domain,
                     const char *operation, const char *password)
{
    char *prefix = NULL, *timestamp = NULL, *path = NULL, *user = NULL;
    char *p;
    unsigned int i;
    int status;
    int lock = -1, fd = -1;
    krb5_error_code retval;

    if (config->queue_dir == NULL)
        return 0;
    prefix = queue_prefix(ctx, principal, domain, operation);
    if (prefix == NULL)
        return 0;

    /*
     * Lock the queue before the timestamp so that another writer coming up
     * at the same time can't get an earlier timestamp.
     */
    lock = lock_queue(config);
    timestamp = queue_timestamp();
    if (timestamp == NULL)
        goto fail;

    /* Find a unique filename for the queue file. */
    for (i = 0; i < MAX_QUEUE; i++) {
        if (path != NULL) {
            free(path);
            path = NULL;
        }
        status = asprintf(&path, "%s/%s%s-%02d", config->queue_dir, prefix,
                          timestamp, i);
        if (status < 0)
            goto fail;
        fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0)
            break;
    }

    /*
     * Get the username from the principal and chop off the realm, dealing
     * properly with escaped @ characters.
     */
    retval = krb5_unparse_name(ctx, principal, &user);
    if (retval != 0)
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
    free(user);
    free(prefix);
    free(timestamp);
    free(path);
    return 1;

fail:
    if (fd >= 0) {
        if (path != NULL)
            unlink(path);
        close(fd);
    }
    if (lock >= 0)
        unlock_queue(lock);
    if (user != NULL)
        free(user);
    if (prefix != NULL)
        free(prefix);
    if (timestamp != NULL)
        free(timestamp);
    if (path != NULL)
        free(path);
    return 0;
}
