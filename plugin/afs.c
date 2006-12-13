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

#include <kerberosIV/krb.h>

/* FIXME: These should come from the configuration. */
#define PWSERV_NAME  "service"
#define KADM_SINST   "k4k5"
#define SRVTAB_FILE "/etc/krb5kdc/k4-srvtab"

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

static int
use_key(user, instance, realm, key, returned_key)
des_cblock key, returned_key;
{
  memcpy(returned_key, key, sizeof(des_cblock));
  return 0;
}

static int 
kas_change2(char *rname, char *rinstance, char *rrealm, des_cblock newpw)
{
    char  name[MAXKTCNAMELEN];
    char  instance[MAXKTCNAMELEN];
    char  cell[MAXKTCREALMLEN];
    char  realm[MAXKTCREALMLEN];
    char *lcell;			/* local cellname */
    int	  code;
#ifndef NOT_MY_KEY
    struct kaentryinfo tentry;
#endif
    struct ubik_client *conn;
    struct ktc_encryptionKey mitkey;
    struct ktc_encryptionKey newkey;
    struct ktc_token    token;
#ifndef KA_INTERFACE
    CREDENTIALS admincred;
#endif
    int local=0;	       

    if ((ka_Init(0)) ||	!(lcell = ka_LocalCell())) {
      memset(&newpw, 0, sizeof(newpw));
      syslog(LOG_ERR, "WARNING: pwupdate failed ka_Init");
      return(1);
    }
    strcpy (realm, lcell);
    code = ka_CellToRealm (realm, realm, &local);
    if (code != 0) {
      memset(&newpw, 0, sizeof(newpw));
      syslog(LOG_ERR, "WARNING: pwupdate failed ka_CellToRealm");
      return(1);
    }
    if (strcmp(realm, rrealm)) {
      memset(&newpw, 0, sizeof(newpw));
      syslog(LOG_ERR, "WARNING: pwupdate failed realm mismatch");
      return(1);
    }
    lcstring (cell, realm, sizeof(cell));

    code = read_service_key(PWSERV_NAME, KADM_SINST, realm, 0, SRVTAB_FILE, &mitkey);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed read_service_key");
#ifdef KA_INTERFACE
    if (!code) code = ka_GetAdminToken (PWSERV_NAME, KADM_SINST, realm,
			     &mitkey, 1000, &token, /*!new*/0);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed ka_GetAdminToken");
#else
    if (!code) code = krb_get_svc_in_tkt(PWSERV_NAME, KADM_SINST, realm, KA_ADMIN_NAME, KA_ADMIN_INST, 4, SRVTAB_FILE);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed krb_get_svc_in_tkt");
    if (!code) code = krb_get_cred(KA_ADMIN_NAME, KA_ADMIN_INST, realm, &admincred);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed krb_get_cred");
    if (!code) {
      token.startTime = admincred.issue_date;
      token.endTime = admincred.issue_date + admincred.lifetime;
      token.kvno = admincred.kvno;
      token.ticketLen = admincred.ticket_st.length;
      memcpy(token.ticket, admincred.ticket_st.dat, token.ticketLen);
      memcpy(&token.sessionKey, admincred.session, 8);
    }
#endif
    
    memset(&mitkey, 0, sizeof(mitkey));
    if (!code) code = ka_AuthServerConn (realm, KA_MAINTENANCE_SERVICE, &token, &conn);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed ka_AuthServerConn");
#ifdef KA_INTERFACE
    if (!code) {
        ka_StringToKey(newpw, realm, &newkey);
        code = ka_ChangePassword (rname, rinstance, conn, 0, &newkey);
    }
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed ka_ChangePassword: %s", error_message(code));
#else
    if (!code) code = ubik_Call (KAM_SetPassword, conn, 0, rname, rinstance, 0, newpw);
    if (code)
        syslog(LOG_ERR, "WARNING: pwupdate failed ubik_Call");
#endif

    /* clean up */
    ubik_ClientDestroy(conn);
    rx_Finalize();

    if (code != 0) {
      memset(&newpw, 0, sizeof(newpw));
    }

    if (!code) {
      syslog(LOG_INFO, "pwupdate: '%s.%s@%s' password changed", rname, rinstance, rrealm);
    }

    return(code);

#ifdef NOT_MY_KEY
#ifdef KA_INTERFACE
    if (!code) code = ka_GetAdminToken (rname, rinstance, realm,
			     &newpw, 1000, &token, /*!new*/0);
#else
    if (!code) code = krb_get_in_tkt(rname, rinstance, realm, KA_ADMIN_NAME, KA_ADMIN_INST, 1, use_key, NULL, newpw);
    if (!code) code = krb_get_cred(KA_ADMIN_NAME, KA_ADMIN_INST, realm, &admincred);
    if (!code) {
      token.startTime = admincred.issue_date;
      token.endTime = admincred.issue_date + admincred.lifetime;
      token.kvno = admincred.kvno;
      token.ticketLen = admincred.ticket_st.length;
      memcpy(token.ticket, admincred.ticket_st.dat, token.ticketLen);
      memcpy(&token.sessionKey, admincred.session, 8);
    }
#endif
    if (!code) code = ka_AuthServerConn (realm, KA_MAINTENANCE_SERVICE, &token, &conn);
    if (!code) code = ubik_Call (KAM_GetEntry, conn, 0, rname, rinstance, KAMAJORVERSION, &tentry);
    if (!code) code = ubik_Call (KAM_SetPassword, conn, 0, rname, rinstance, tentry.key_version, newpw);

    /* clean up */
    memset(&newpw, 0, sizeof(newpw));
    ubik_ClientDestroy(conn);
    rx_Finalize();
#endif
}

/* From this call we process AFS error codes into MIT Kerberos errors */
static int 
kas_change(char *rname, char *rinstance, char *rrealm, char * newpw)
{
  int retval;
  des_cblock newkey;

  des_string_to_key(newpw, newkey);

  retval = kas_change2(rname, rinstance, rrealm, newpw);
    
  switch (retval) 
    {
    case 0:
      return 0; /* If we got a zero, no parsing needed! */
      break;
    default:
      return 1;
    }
  return 1;
}

int
pwupdate_afs_change(struct plugin_config *config, krb5_context ctx,
                    krb5_principal principal, char *password, int pwlen,
                    char *errstr, int errstrlen)
{
    krb5_error_code retval;
    char aname[ANAME_SZ+1], inst[INST_SZ+1], realm[REALM_SZ+1];

    *errstr = '\0';

    retval = krb5_524_conv_principal(ctx, principal, aname, inst, realm);
    if (retval) {
        syslog(LOG_ERR, "WARNING: pwupdate failed converting principal to K4: %d", retval);
        snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(retval));
        return (1);
    }
    return kas_change(aname, inst, config->afs_realm, password);
}
