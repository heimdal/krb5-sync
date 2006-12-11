/*
 * Modify an account on an AD server to enable or disable it
 */

#include <errno.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ldap.h>
#include <krb5.h>
#include <com_err.h>

#define CACHE_NAME "MEMORY:ad_modify"
#define UF_ACCOUNTDISABLE 0x02

static int ad_interact_sasl(LDAP *, unsigned, void *, void *);

int main(int argc, char *argv[])
{
	krb5_context context;
	krb5_principal client = NULL;
	krb5_keytab kt;
	krb5_ccache cc;
	krb5_creds creds;
	krb5_get_init_creds_opt options;
	krb5_error_code retval;
	char ktname[256];

	LDAP *ld;
	LDAPMessage *res;
	LDAPMod mod, *mod_array[2];
	char ldapuri[256], ldapbase[256], ldapdn[256], *dname, *lb, *dn;
	char *attrs[] = { "userAccountControl", NULL }, *strvals[2];
	char **vals;
	int option, enable;
	unsigned int acctcontrol;

        openlog("ad-modify", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_INFO, "running ad-modify to %s %s", argv[6], argv[4]);

	if (argc != 7) {
                syslog(LOG_ERR, "incorrect argc (%d != 7)", argc);
		exit(1);
	}

	if (strcmp(argv[6], "enable") == 0) {
		enable = 1;
	} else if (strcmp(argv[6], "disable") == 0) {
		enable = 0;
	} else {
                syslog(LOG_ERR, "incorrect final argument: %s", argv[6]);
		exit(1);
	}

	/* Point SASL at the memory cache we're about to create. */
	if (putenv("KRB5CCNAME=" CACHE_NAME) != 0) {
                syslog(LOG_ERR, "putenv of KRB5CCNAME failed: %m");
		exit(1);
	}

	/*
	 * Use the supplied keytab to initialize the credentials
	 * for the LDAP connection.  I wish this was eaiser.
	 */

	if ((retval = krb5_init_context(&context))) {
		syslog(LOG_ERR, "init_context failed: %s",
                       error_message(retval));
		exit(1);
	}

	snprintf(ktname, sizeof(ktname), "FILE:%s", argv[2]);
	ktname[sizeof(ktname) - 1] = '\0';

	if ((retval = krb5_kt_resolve(context, ktname, &kt))) {
		syslog(LOG_ERR, "Unable to resolve keytab: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_parse_name(context, argv[3], &client))) {
		syslog(LOG_ERR, "Unable to parse client name: %s",
                       error_message(retval));
		exit(1);
	}

	krb5_get_init_creds_opt_init(&options);
	memset((void *) &creds, 0, sizeof(creds));

	if ((retval = krb5_get_init_creds_keytab(context, &creds, client,
						 kt, 0, NULL, &options))) {
		syslog(LOG_ERR, "Unable to get initial credentials: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_resolve(context, CACHE_NAME, &cc))) {
		syslog(LOG_ERR, "Unable to resolve memory cache: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_initialize(context, cc, client))) {
		syslog(LOG_ERR, "Unable to initialize memory cache: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_store_cred(context, cc, &creds))) {
		syslog(LOG_ERR, "Unable to store credentials in cache: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_close(context, cc))) {
		syslog(LOG_ERR, "Unable to close memory cache: %s",
                       error_message(retval));
		exit(1);
	}

	if ((retval = krb5_kt_close(context, kt))) {
		syslog(LOG_ERR, "Unable to close keytab: %s",
                       error_message(retval));
		exit(1);
	}
	
	krb5_free_cred_contents(context, &creds);
	krb5_free_principal(context, client);

	/*
	 * Okay, Kerberos is all done.  Now do the LDAP magic.
	 */

	snprintf(ldapuri, sizeof(ldapuri), "ldap://%s", argv[1]);
	ldapuri[sizeof(ldapuri) - 1] = '\0';

	if ((retval = ldap_initialize(&ld, ldapuri)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap initialization failed: %s",
                       ldap_err2string(retval));
		exit(1);
	}

	option = LDAP_VERSION3;
	if ((retval = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
				      &option)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap protocol selection failed: %s",
                       ldap_err2string(retval));
		exit(1);
	}

	if ((retval = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL,
						    NULL, LDAP_SASL_QUIET,
						    ad_interact_sasl,
						    NULL)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap bind failed: %s",
                       ldap_err2string(retval));
                ldap_perror(ld, "sasl_interactive_bind");
		exit(1);
	}

	/*
 	 * Convert the domain name to a DN; since we're always
	 * working in the Users CN, just start out with that.
	 */

	memset(ldapbase, 0, sizeof(ldapbase));
	strcpy(ldapbase, "ou=Accounts,dc=");
	lb = ldapbase + strlen(ldapbase);

	for (dname = argv[5]; *dname; dname++) {
		if (*dname == '.') {
			strcpy(lb, ",dc=");
			lb += 4;
		} else
			*lb++ = *dname;
		if (strlen(ldapbase) > sizeof(ldapbase) - 2)
			break;
	}

	/*
	 * Since all we know is the username, first we have to
	 * query the server to get back the CN for the user to
	 * construct the full DN.
	 */
	snprintf(ldapdn, sizeof(ldapdn), "(samAccountName=%s)", argv[4]);
	ldapdn[sizeof(ldapdn) - 1] = '\0';

	retval = ldap_search_s(ld, ldapbase, LDAP_SCOPE_SUBTREE,
			       ldapdn, attrs, 0, &res);

	if (retval != LDAP_SUCCESS) {
                syslog(LOG_ERR, "ldap search on \"%s\" failed: %s",
			ldapdn, ldap_err2string(retval));
		exit(1);
	}

	if (ldap_count_entries(ld, res) == 0) {
                syslog(LOG_ERR, "No such user \"%s\" found", argv[4]);
		exit(1);
	}

	res = ldap_first_entry(ld, res);

	dn = ldap_get_dn(ld, res);

	if (ldap_msgtype(res) != LDAP_RES_SEARCH_ENTRY) {
                syslog(LOG_ERR, "Expected msgtype of RES_SEARCH_ENTRY (0x61), "
			"but got type %x instead", ldap_msgtype(res));
		exit(1);
	}

	vals = ldap_get_values(ld, res, "userAccountControl");
	ldap_msgfree(res);

	if (ldap_count_values(vals) != 1) {
                syslog(LOG_ERR, "We expected 1 value for userAccoutControl, "
			"and we got %d.  Aborting!",
			ldap_count_values(vals));
		exit(1);
	}

	if (sscanf(vals[0], "%u", &acctcontrol) != 1) {
                syslog(LOG_ERR, "Unable to parse userAccountControl (%s)",
			vals[0]);
		exit(1);
	}

	ldap_value_free(vals);

	if (enable) {
		acctcontrol &= ~UF_ACCOUNTDISABLE;
	} else {
		acctcontrol |= UF_ACCOUNTDISABLE;
	}

	memset((void *) &mod, 0, sizeof(mod));

	mod.mod_op = LDAP_MOD_REPLACE;
	mod.mod_type = "userAccountControl";
	snprintf(ldapdn, sizeof(ldapdn), "%u", acctcontrol);
	ldapdn[sizeof(ldapdn) - 1] = '\0';
	strvals[0] = ldapdn;
	strvals[1] = NULL;
	mod.mod_vals.modv_strvals = strvals;
	
	mod_array[0] = &mod;
	mod_array[1] = NULL;

	if ((retval = ldap_modify_s(ld, dn, mod_array)) != LDAP_SUCCESS) {
		syslog(LOG_ERR, "LDAP database modification failed: %s",
                       ldap_err2string(retval));
		exit(1);
	}

        syslog(LOG_INFO, "successfully set account %s to %s", argv[4],
               argv[6]);

	ldap_unbind_s(ld);
	exit(0);
}

/*
 * This works ... for now.  Sigh.
 */

static int
ad_interact_sasl(LDAP *ld, unsigned flags, void *defaults, void *interact)
{
	return 0;
}
