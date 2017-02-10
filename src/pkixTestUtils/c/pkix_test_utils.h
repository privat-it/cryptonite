/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKIXTESTUTILS_H
#define CRYPTONITE_PKIXTESTUTILS_H

#include "stacktrace.h"
#include "asn1_module.h"
#include "oids.h"

#define ASSERT_EQUALS_ASN(asn_type, expected, actual) if (!asn_equals_core(asn_type, expected, actual, __FILE__, __LINE__)) goto cleanup;
#define ASSERT_EQUALS_OID(_id, _oid) if (!asn_equals_oid_core(_id, _oid, __FILE__, __LINE__)) goto cleanup;

#define ASSERT_ASN_ALLOC(obj) ((obj) = calloc(1, sizeof(*(obj))));                               \
    if ((obj) == NULL) { ERROR_ADD(RET_MEMORY_ALLOC_ERROR); goto cleanup; }

bool asn_equals_core(asn_TYPE_descriptor_t *type, const void *expected, const void *actual, const char *file,
        const size_t line);
bool asn_equals_oid_core(const OidId id, const OBJECT_IDENTIFIER_t *oid, const char *file, const size_t line);

#endif //CRYPTONITE_PKIXTESTUTILS_H
