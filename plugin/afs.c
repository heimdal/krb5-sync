/*
 * afs.c
 *
 * AFS kaserver synchronization functions.
 *
 * Implements the interface that talks to an AFS kaserver for password
 * changes.
 */

#include "config.h"

#include <errno.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef HAVE_KERBEROSIV_KRB_H
# include <kerberosIV/krb.h>
# include <kerberosIV/des.h>
#else
# include <krb.h>
# include <des.h>
#endif

#include <afs/param.h>
#include <afs/stds.h>
#include <sys/types.h>
#include <rx/xdr.h>
#include <ubik.h>
#include <afs/auth.h>
#include <afs/cellconfig.h>
#include <afs/kauth.h>
#include <afs/kautils.h>

#ifndef KRB5_KRB4_COMPAT
# define ANAME_SZ 40
# define INST_SZ  40
# define REALM_SZ 40
#endif

#include <plugin/internal.h>

/*
 * Change a password in the AFS kaserver.  Takes the module configuration, a
 * Kerberos context, the principal whose password is being changed (we will
 * derive the AFS principal with krb5_524_conv_principal and then changing its
 * realm), the new password and its length, and a buffer into which to write
 * error messages and its length.
 */
int
pwupdate_afs_change(struct plugin_config *config, krb5_context ctx,
                    krb5_principal principal, char *password,
                    int pwlen UNUSED, char *errstr, int errstrlen)
{
    krb5_error_code ret;
    char aname[ANAME_SZ + 1], admin_aname[ANAME_SZ + 1];
    char inst[INST_SZ + 1], admin_inst[INST_SZ + 1];
    char realm[REALM_SZ + 1], admin_realm[REALM_SZ + 1];
    char cell[MAXKTCREALMLEN];
    char *local_cell;
    char local_realm[MAXKTCREALMLEN];
    int local = 0;
    int code = 0;
    struct ubik_client *conn;
    struct ktc_encryptionKey mitkey, newkey;
    struct ktc_token token;

    /*
     * First, figure out what principal we're dealing with and then check that
     * the realms are sane.  The original code required that the realm in
     * which we're changing passwords matches the local realm from AFS's
     * perspective.  I'm not sure if that's actually required, but preserve
     * that check for right now just in case.
     */
    ret = krb5_524_conv_principal(ctx, principal, aname, inst, realm);
    if (ret != 0) {
        snprintf(errstr, errstrlen, "failed converting principal to K4: %s",
                 error_message(ret));
        return 1;
    }
    if (strlen(config->afs_realm) > sizeof(realm) - 1) {
        snprintf(errstr, errstrlen, "AFS realm %s longer than maximum length"
                 " of %ld", config->afs_realm, (long) sizeof(realm));
        return 1;
    }
    strcpy(realm, config->afs_realm);
    if (ka_Init(0) != 0) {
        snprintf(errstr, errstrlen, "ka_Init failed");
        return 1;
    }
    local_cell = ka_LocalCell();
    if (local_cell == NULL || strlen(local_cell) > sizeof(local_realm) - 1) {
        snprintf(errstr, errstrlen, "cannot obtain local cell");
        return 1;
    }
    strcpy(local_realm, local_cell);
    code = ka_CellToRealm(local_realm, local_realm, &local);
    if (code != 0) {
        snprintf(errstr, errstrlen, "cannot obtain local realm");
        return 1;
    }
    if (strcmp(local_realm, realm) != 0) {
        snprintf(errstr, errstrlen, "realm mismatch: local AFS realm (%s)"
                 " must match principal realm (%s)", local_realm, realm);
        return 1;
    }
    lcstring(cell, realm, sizeof(cell));

    /*
     * Okay, annoying setup done.  Now we obtain an admin token from our
     * srvtab.  This principal will have to have the ADMIN flag set in the
     * kaserver database.
     *
     * If a ktc_encryptionKey is never not the right size or format to take
     * the results of read_service_key, we will be sad.  Yay, type checking.
     */
    code = kname_parse(admin_aname, admin_inst, admin_realm,
                       config->afs_principal);
    if (code != 0) {
        snprintf(errstr, errstrlen, "cannot parse AFS principal \"%s\"",
                 config->afs_principal);
        return 1;
    }
    code = read_service_key(admin_aname, admin_inst, config->afs_realm, 0,
                            config->afs_srvtab, (char *) &mitkey);
    if (code != 0) {
        snprintf(errstr, errstrlen, "unable to get key from srvtab \"%s\" for"
                 " principal \"%s.%s@%s\"", config->afs_srvtab, admin_aname,
                 admin_inst, config->afs_realm);
        return 1;
    }
    code = ka_GetAdminToken(admin_aname, admin_inst, config->afs_realm,
                            &mitkey, 1000, &token, 0);
    if (code != 0) {
        snprintf(errstr, errstrlen, "ka_GetAdminToken failed: %s",
                 error_message(code));
        return 1;
    }
    memset(&mitkey, 0, sizeof(mitkey));

    /*
     * Finally, we can open a connection to the kaserver and change the
     * password.
     */
    code = ka_AuthServerConn(realm, KA_MAINTENANCE_SERVICE, &token, &conn);
    if (code != 0) {
        snprintf(errstr, errstrlen, "ka_AuthServerConn failed: %s",
                 error_message(code));
        return 1;
    }
    ka_StringToKey(password, realm, &newkey);
    code = ka_ChangePassword(aname, inst, conn, 0, &newkey);
    if (code != 0) {
        snprintf(errstr, errstrlen, "ka_ChangePassword failed: %s",
                 error_message(code));
        memset(&newkey, 0, sizeof(newkey));
        ubik_ClientDestroy(conn);
        rx_Finalize();
        return 1;
    }

    /* Success.  Log success, clean up, and return. */
    syslog(LOG_INFO, "pwupdate: %s.%s@%s password changed", aname, inst,
           realm);
    ubik_ClientDestroy(conn);
    rx_Finalize();
    return 0;
}
