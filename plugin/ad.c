/*
 * ad.c
 *
 * Active Directory synchronization functions.
 *
 * Implements the interface that talks to Active Directory for both password
 * changes and for account status updates.
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <plugin/internal.h>

int
pwupdate_ad_change(struct plugin_config *config, krb5_context ctx,
                   krb5_principal principal, char *password, int pwlen,
                   char *errstr, int errstrlen)
{
    krb5_error_code ret;
    char *targpname = NULL;
    krb5_ccache ccache;
    int result_code;
    krb5_data result_code_string, result_string;
    int code = 0;

    ret = krb5_cc_default(ctx, &ccache);
    if (ret != 0) {
        if (ret == KRB5_CC_NOTFOUND)
	    syslog(LOG_ERR, "WARNING: pwupdate failed: no kerberos credentials");
        else 
	    syslog(LOG_ERR, "WARNING: pwupdate failed opening kerberos ccache: %d", ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	return (1);
    }

    ret = krb5_unparse_name(ctx, principal, &targpname);
    if (ret != 0) {
	syslog(LOG_ERR, "WARNING: pwupdate failed parsing target kerberos principal: %d", ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	return (1);
    }

    krb5_set_principal_realm(ctx, principal, config->ad_realm);
    /* If a more comprehensive rewrite function is needed, it goes here. */

    ret = krb5_set_password_using_ccache(ctx, ccache, password, principal,
                                         &result_code, &result_code_string,
                                         &result_string);
    if (ret != 0) {
	syslog(LOG_ERR, "WARNING: pwupdate failed changing password for %s: %d", targpname, ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	code = 1;
	goto ret;
    }
    if (result_code) {
	syslog(LOG_ERR, "WARNING: pwupdate error changing password for %s: %.*s%s%.*s\n", targpname,
               result_code_string.length, result_code_string.data,
               result_string.length?": ":"",
               result_string.length, result_string.data);
	code = 2;
	snprintf(errstr, errstrlen, "%.*s%s%.*s", result_code_string.length, 
		 result_code_string.data, 
		 result_string.length?": ":"", 
		 result_string.length, result_string.data); 

	goto ret;
    }

    free(result_string.data);
    free(result_code_string.data);

    syslog(LOG_INFO, "pwupdate: %s: password changed", targpname);
    snprintf(errstr, errstrlen, "Password changed");

 ret:
    krb5_free_unparsed_name(ctx, targpname);
    return code;
}
