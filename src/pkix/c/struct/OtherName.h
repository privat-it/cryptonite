/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherName_H_
#define    _OtherName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherName */
typedef struct OtherName {
    OBJECT_IDENTIFIER_t     type_id;
    ANY_t     value;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherName_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
