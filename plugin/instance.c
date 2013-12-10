/*
 * Get data about instances in the Kerberos KDC database.
 *
 * The functions in this file use the Kerberos kadm5srv library API to look up
 * information about instances of a principal in the local Kerberos KDC
 * database.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2013
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <config.h>
#include <portable/kadmin.h>
#include <portable/krb5.h>
#include <portable/system.h>

#include <plugin/internal.h>
#include <util/macros.h>


/*
 * Given a principal and an instance, return true if the principal is a
 * one-part name and the principal formed by adding the instance as a second
 * part is found in the local Kerberos database.  Returns false if it is not
 * or on any other error.
 */
krb5_error_code
sync_instance_exists(krb5_context ctx, krb5_principal base,
                     const char *instance, bool *exists)
{
    krb5_principal princ = NULL;
    krb5_error_code code;
    const char *realm;
    kadm5_config_params params;
    void *handle = NULL;
    int mask;
    kadm5_principal_ent_rec ent;

    /* Default to assuming the principal doesn't exist. */
    *exists = false;

    /* Principals must have exactly one component. */
    if (krb5_principal_get_num_comp(ctx, base) != 1)
        return 0;
    
    /* Form a new principal from the old principal plus the instance. */
    realm = krb5_principal_get_realm(ctx, base);
    if (realm == NULL) {
        code = KADM5_BAD_PRINCIPAL;
        krb5_set_error_message(ctx, code, "cannot get realm of principal");
        goto fail;
    }
    code = krb5_build_principal(ctx, &princ, strlen(realm), realm,
                                krb5_principal_get_comp_string(ctx, base, 0),
                                instance, (char *) 0);
    if (code != 0)
        goto fail;

    /* Open the local KDB and look up this new principal. */
    memset(&params, 0, sizeof(params));
    params.realm = (char *) realm;
    params.mask = KADM5_CONFIG_REALM;
    code = kadm5_init_with_skey_ctx(ctx, (char *) "kadmin/admin", NULL, NULL,
                                    &params, KADM5_STRUCT_VERSION,
                                    KADM5_API_VERSION_2, &handle);
    if (code != 0)
        goto fail;
    mask = KADM5_ATTRIBUTES | KADM5_PW_EXPIRATION;
    code = kadm5_get_principal(handle, princ, &ent, mask);
    if (code != 0 && code != KADM5_UNK_PRINC)
        goto fail;
    if (code == 0) {
        *exists = true;
        kadm5_free_principal_ent(handle, &ent);
    }
    kadm5_destroy(handle);
    krb5_free_principal(ctx, princ);
    return 0;

fail:
    if (princ != NULL)
        krb5_free_principal(ctx, princ);
    return code;
}
