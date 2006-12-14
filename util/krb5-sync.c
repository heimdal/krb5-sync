/*
 * krb5-sync.c
 *
 * Command-line access to the krb5-sync kadmind plugin.
 *
 * This program provides command-line access to the functionality of the
 * krb5-sync kadmind plugin.  Using it, one can push password changes or
 * enabled/disabled status according to the same configuration used by the
 * plugin.  It's primarily intended for testing, but can also be used to
 * synchronize changes when the plugin previously failed for some reason.
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <plugin/internal.h>

int
main(int argc, char *argv[])
{
    int option;
    int enable = 0;
    int disable = 0;
    char *password = NULL;
    char *user;
    void *data;
    krb5_context ctx;
    krb5_error_code ret;
    krb5_principal principal;
    char errbuf[BUFSIZ];
    int status;

    while ((option = getopt(argc, argv, "dep:")) != EOF) {
        switch (option) {
        case 'd':
            if (enable) {
                fprintf(stderr, "Cannot specify both -d and -e\n");
                exit(1);
            }
            disable = 1;
            break;
        case 'e':
            if (disable) {
                fprintf(stderr, "Cannot specify both -d and -e\n");
                exit(1);
            }
            enable = 1;
            break;
        case 'p':
            password = optarg;
            break;
        default:
            fprintf(stderr, "Usage: krb5-sync [-d | -e] [-p <pass>] <user>\n");
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 1) {
        fprintf(stderr, "Usage: krb5-sync [-d | -e] [-p <pass>] <user>\n");
        exit(1);
    }
    user = argv[0];
    if (!enable && !disable && password == NULL) {
        fprintf(stderr, "No action specified\n");
        exit(1);
    }

    /* Create a Kerberos context for plugin initialization. */
    ret = krb5_init_context(&ctx);
    if (ret != 0) {
        fprintf(stderr, "Cannot initialize Kerberos context: %s\n",
                error_message(ret));
        exit(1);
    }

    /* Initialize the plugin. */
    if (pwupdate_init(ctx, &data)) {
        fprintf(stderr, "Plugin initialization failed\n");
        exit(1);
    }

    /* Convert the user into a principal. */
    ret = krb5_parse_name(ctx, user, &principal);
    if (ret != 0) {
        fprintf(stderr, "Cannot parse user %s into principal: %s", user,
                error_message(ret));
        exit(1);
    }

    /* Password changes first. */
    if (password != NULL) {
        status = pwupdate_precommit_password(data, principal, password,
                                             strlen(password), errbuf,
                                             sizeof(errbuf));
        if (status != 0) {
            fprintf(stderr, "Precommit failed (%d): %s\n", status, errbuf);
            exit(1);
        }
        printf("Password precommit succeeded\n");
        status = pwupdate_postcommit_password(data, principal, password,
                                              strlen(password), errbuf,
                                              sizeof(errbuf));
        if (status != 0) {
            fprintf(stderr, "Postcommit failed (%d): %s\n", status, errbuf);
            exit(1);
        }
        printf("Password postcommit succeeded\n");
    }

    /* Now, enable or disable. */
    if (enable || disable) {
        status = pwupdate_postcommit_status(data, principal, enable, errbuf,
                                            sizeof(errbuf));
        if (status != 0) {
            fprintf(stderr, "Status failed (%d): %s\n", status, errbuf);
            exit(1);
        }
        printf("Status change succeeded\n");
    }

    exit(0);
}
