/*
 * Utility functions for krb5-sync testing.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2012, 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#ifndef TAP_SYNC_H
#define TAP_SYNC_H 1

#include <config.h>
#include <tests/tap/macros.h>

BEGIN_DECLS

/*
 * Block processing by creating a dummy queue file.  Takes the queue
 * directory, the username (as used for queuing), and the operation to block.
 * Calls bail on failure.
 */
void sync_queue_block(const char *queue, const char *user, const char *op);
void sync_queue_unblock(const char *queue, const char *user, const char *op);

/*
 * Check queue files for the correct information.  Reports results with the
 * normal TAP functions, and calls bail on OS failures.
 */
void sync_queue_check_enable(const char *queue, const char *user, bool);
void sync_queue_check_password(const char *queue, const char *user,
                               const char *password);

END_DECLS

#endif /* TAP_SYNC_H */
