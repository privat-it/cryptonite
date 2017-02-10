/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeTypeAndValue_H_
#define    _AttributeTypeAndValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttributeType.h"
#include "AttributeValue.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeTypeAndValue */
typedef struct AttributeTypeAndValue {
    AttributeType_t     type;
    AttributeValue_t     value;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttributeTypeAndValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeTypeAndValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeTypeAndValue_desc(void);

#ifdef __cplusplus
}
#endif

#endif
