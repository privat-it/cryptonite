/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRevRefs_H_
#define    _OtherRevRefs_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherRevRefType.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRevRefs */
typedef struct OtherRevRefs {
    OtherRevRefType_t     otherRevRefType;
    ANY_t     otherRevRefs;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherRevRefs_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRevRefs_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRevRefs_desc(void);

#ifdef __cplusplus
}
#endif

#endif
