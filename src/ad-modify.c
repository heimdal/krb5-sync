/*
 * Modify an account on an AD server to enable or disable it
 */

#include <errno.h>
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

	if (argc != 7) {
		fprintf(stderr, "Usage: %s \\\n\tldap-server keytab "
			"client-principal username windows-domain \\\n\t"
			"enable|disable\n",
			argv[0]);
		exit(1);
	}

	if (strcmp(argv[6], "enable") == 0) {
		enable = 1;
	} else if (strcmp(argv[6], "disable") == 0) {
		enable = 0;
	} else {
		fprintf(stderr, "Final argument must be one of \"enable\" "
			"or \"disable\"\n");
		exit(1);
	}

	/* Point SASL at the memory cache we're about to create. */
	if (putenv("KRB5CCNAME=" CACHE_NAME) != 0) {
		fprintf(stderr, "putenv of KRB5CCNAME failed: %s\n",
			strerror(errno));
		exit(1);
	}

	/*
	 * Use the supplied keytab to initialize the credentials
	 * for the LDAP connection.  I wish this was eaiser.
	 */

	if ((retval = krb5_init_context(&context))) {
		fprintf(stderr, "init_context failed: %s\n",
			error_message(retval));
		exit(1);
	}

	snprintf(ktname, sizeof(ktname), "FILE:%s", argv[2]);
	ktname[sizeof(ktname) - 1] = '\0';

	if ((retval = krb5_kt_resolve(context, ktname, &kt))) {
		fprintf(stderr, "Unable to resolve keytab: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_parse_name(context, argv[3], &client))) {
		fprintf(stderr, "Unable to parse client name: %s\n",
			error_message(retval));
		exit(1);
	}

	krb5_get_init_creds_opt_init(&options);
	memset((void *) &creds, 0, sizeof(creds));

	if ((retval = krb5_get_init_creds_keytab(context, &creds, client,
						 kt, 0, NULL, &options))) {
		fprintf(stderr, "Unable to get initial credentials: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_resolve(context, CACHE_NAME, &cc))) {
		fprintf(stderr, "Unable to resolve memory cache: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_initialize(context, cc, client))) {
		fprintf(stderr, "Unable to initialize memory cache: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_store_cred(context, cc, &creds))) {
		fprintf(stderr, "Unable to store credentials in cache: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_cc_close(context, cc))) {
		fprintf(stderr, "Unable to close memory cache: %s\n",
			error_message(retval));
		exit(1);
	}

	if ((retval = krb5_kt_close(context, kt))) {
		fprintf(stderr, "Unable to close keytab: %s\n",
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
		fprintf(stderr, "ldap initialization failed: %s\n",
			ldap_err2string(retval));
		exit(1);
	}

	option = LDAP_VERSION3;
	if ((retval = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
				      &option)) != LDAP_SUCCESS) {
		fprintf(stderr, "ldap protocol selection failed: %s\n",
			ldap_err2string(retval));
		exit(1);
	}

	if ((retval = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL,
						    NULL, LDAP_SASL_QUIET,
						    ad_interact_sasl,
						    NULL)) != LDAP_SUCCESS) {
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
		fprintf(stderr, "ldap search on \"%s\" failed: %s\n",
			ldapdn, ldap_err2string(retval));
		exit(1);
	}

	if (ldap_count_entries(ld, res) == 0) {
		fprintf(stderr, "No such user \"%s\" found.\n", argv[4]);
		exit(1);
	}

	res = ldap_first_entry(ld, res);

	dn = ldap_get_dn(ld, res);

	if (ldap_msgtype(res) != LDAP_RES_SEARCH_ENTRY) {
		fprintf(stderr, "Expected msgtype of RES_SEARCH_ENTRY (0x61), "
			"but got type %x instead\n", ldap_msgtype(res));
		exit(1);
	}

	vals = ldap_get_values(ld, res, "userAccountControl");
	ldap_msgfree(res);

	if (ldap_count_values(vals) != 1) {
		fprintf(stderr, "We expected 1 value for userAccoutControl, "
			"and we got %d.  Aborting!\n",
			ldap_count_values(vals));
		exit(1);
	}

	if (sscanf(vals[0], "%u", &acctcontrol) != 1) {
		fprintf(stderr, "Unable to parse userAccountControl (%s)\n",
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
		fprintf(stderr, "LDAP database modification failed: %s\n",
			ldap_err2string(retval));
		exit(1);
	}

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
