/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkix_test_utils.h"

#include "asn1_utils.h"
#include "test_utils.h"
#include "pkix_macros_internal.h"

bool asn_equals_core(asn_TYPE_descriptor_t *type, const void *expected, const void *actual, const char *file,
        const size_t line)
{
    int ret = RET_OK;
    bool check;

    if (!(check = asn_equals(type, expected, actual))) {
        PR("\n-----------------------------------------------------------------------------------------------\n");
        PR("%s:%d\n\n", file, (unsigned int)line);
        PR("EXPECTED:\n");
        DO(xer_fprint(stdout, type, (void *)expected));
        PR("ACTUAL:\n");
        DO(xer_fprint(stdout, type, (void *)actual));
        PR("\n-----------------------------------------------------------------------------------------------\n");
    }

cleanup:

    return check;
}

bool asn_equals_oid_core(const OidId id, const OBJECT_IDENTIFIER_t *oid, const char *file, const size_t line)
{
    int ret = RET_OK;
    bool check = false;
    OBJECT_IDENTIFIER_t *ext_oid = NULL;

    CHECK_NOT_NULL(ext_oid = oids_get_oid_by_id(id));

    if (!(check = asn_equals(&OBJECT_IDENTIFIER_desc, ext_oid, oid))) {
        PR("\n-----------------------------------------------------------------------------------------------\n");
        PR("%s:%d\n\n", file, (unsigned int)line);
        PR("EXPECTED:\n");
        DO(xer_fprint(stdout, &OBJECT_IDENTIFIER_desc, (void *)ext_oid));
        PR("ACTUAL:\n");
        DO(xer_fprint(stdout, &OBJECT_IDENTIFIER_desc, (void *)oid));
        PR("\n-----------------------------------------------------------------------------------------------\n");
    }

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, ext_oid);

    return check;
}
