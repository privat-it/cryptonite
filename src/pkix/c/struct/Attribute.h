/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Attribute_H_
#define    _Attribute_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "AttributeValue.h"
#include "asn_SET_OF.h"
#include "constr_SET_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attribute */
typedef struct Attribute {
    OBJECT_IDENTIFIER_t     type;
    struct value {
        A_SET_OF(AttributeValue_t) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } value;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Attribute_t;

/* Implementation */
extern asn_TYPE_descriptor_t Attribute_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Attribute_desc(void);

#ifdef __cplusplus
}
#endif

#endif
