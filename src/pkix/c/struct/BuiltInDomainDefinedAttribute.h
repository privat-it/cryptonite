/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BuiltInDomainDefinedAttribute_H_
#define    _BuiltInDomainDefinedAttribute_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* BuiltInDomainDefinedAttribute */
typedef struct BuiltInDomainDefinedAttribute {
    PrintableString_t     type;
    PrintableString_t     value;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} BuiltInDomainDefinedAttribute_t;

/* Implementation */
extern asn_TYPE_descriptor_t BuiltInDomainDefinedAttribute_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BuiltInDomainDefinedAttribute_desc(void);

#ifdef __cplusplus
}
#endif

#endif
