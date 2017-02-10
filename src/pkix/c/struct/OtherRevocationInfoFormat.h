/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRevocationInfoFormat_H_
#define    _OtherRevocationInfoFormat_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRevocationInfoFormat */
typedef struct OtherRevocationInfoFormat {
    OBJECT_IDENTIFIER_t     otherRevInfoFormat;
    ANY_t     otherRevInfo;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherRevocationInfoFormat_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRevocationInfoFormat_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRevocationInfoFormat_desc(void);

#ifdef __cplusplus
}
#endif

#endif
