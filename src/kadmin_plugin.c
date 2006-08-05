#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>

#include <krb5.h>
#include <com_err.h>

static struct lctx {
    char *realm;
    /* server, port */
} l_context;

int pwupdate_init(krb5_context context, void **pwcontext)
{
    *pwcontext = &l_context;
    l_context.realm = strdup(FOREIGNREALM);
    return 0;
}

int pwupdate_precommit_password(void *context, krb5_principal principal, char *password, int pwlen,
				char *errstr, int errstrlen)
{
    krb5_error_code ret;
    krb5_context fcontext;
    char *pname = NULL;
    char *targpname = NULL;
    krb5_ccache ccache;
    int result_code;
    krb5_data result_code_string, result_string;
    int code = 0;

    if (ret = krb5_init_context(&fcontext)) {
	krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate failed initializing kerberos library: %d", ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	return (1);
    }

    if (ret = krb5_cc_default(fcontext, &ccache)) {
        if (ret == KRB5_CC_NOTFOUND)
	    krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate failed: no kerberos credentials");
        else 
	    krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate failed opening kerberos ccache: %d", ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	return (1);
    }

    if (ret = krb5_unparse_name(fcontext, principal, &targpname)) {
	krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate failed parsing target kerberos principal: %d", ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	return (1);
    }

    krb5_set_principal_realm(fcontext, principal, ((struct lctx *)context)->realm);
    /* If a more comprehensive rewrite function is needed, it goes here. */

    if (ret = krb5_set_password_using_ccache(fcontext, ccache, password, principal,
                                &result_code, &result_code_string,
                                &result_string)) {
	krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate failed changing password for %s: %d", targpname, ret);
	snprintf(errstr, errstrlen, "Password synchronization failure: %s", error_message(ret));
	code = 1;
	goto ret;
    }
    if (result_code) {
	krb5_klog_syslog(LOG_ERR, "WARNING: pwupdate error changing password for %s: %.*s%s%.*s\n", targpname,
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

    krb5_klog_syslog(LOG_INFO, "pwupdate: %s: password changed", targpname);
    snprintf(errstr, errstrlen, "Password changed");

 ret:
    krb5_free_unparsed_name(fcontext, targpname);
    return code;
}

int pwupdate_postcommit_password(void *context, krb5_principal principal, char *password, int pwlen,
				 char *errstr, int errstrlen)
{
    return 0;
}

void pwupdate_close(void *context)
{
    if (l_context.realm) free(l_context.realm);
    return 0;
}
