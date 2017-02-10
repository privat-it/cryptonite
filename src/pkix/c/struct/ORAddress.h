/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ORAddress_H_
#define    _ORAddress_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BuiltInStandardAttributes.h"
#include "NULL.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct BuiltInDomainDefinedAttributes;

/* ORAddress */
typedef struct ORAddress {
    BuiltInStandardAttributes_t     built_in_standard_attributes;
    struct BuiltInDomainDefinedAttributes    *built_in_domain_defined_attributes    /* OPTIONAL */;
    NULL_t    *extension_attributes    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ORAddress_t;

/* Implementation */
extern asn_TYPE_descriptor_t ORAddress_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ORAddress_desc(void);

#ifdef __cplusplus
}
#endif

#endif
