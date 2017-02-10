/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRevVals_H_
#define    _OtherRevVals_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherRevValType.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRevVals */
typedef struct OtherRevVals {
    OtherRevValType_t     otherRevValType;
    ANY_t     otherRevVals;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherRevVals_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRevVals_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRevVals_desc(void);

#ifdef __cplusplus
}
#endif

#endif
