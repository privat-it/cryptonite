/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherHash_H_
#define    _OtherHash_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherHashAlgAndValue.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OtherHash_PR {
    OtherHash_PR_NOTHING,    /* No components present */
    OtherHash_PR_otherHash
} OtherHash_PR;

/* OtherHash */
typedef struct OtherHash {
    OtherHash_PR present;
    union OtherHash_u {
        OtherHashAlgAndValue_t     otherHash;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherHash_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherHash_desc(void);

#ifdef __cplusplus
}
#endif

#endif
