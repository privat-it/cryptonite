/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherKeyAttribute_H_
#define    _OtherKeyAttribute_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherKeyAttribute */
typedef struct OtherKeyAttribute {
    OBJECT_IDENTIFIER_t     keyAttrId;
    ANY_t    *keyAttr    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherKeyAttribute_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherKeyAttribute_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherKeyAttribute_desc(void);

#ifdef __cplusplus
}
#endif

#endif
