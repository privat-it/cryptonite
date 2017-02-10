/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherHashAlgAndValue_H_
#define    _OtherHashAlgAndValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "OtherHashValue.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherHashAlgAndValue */
typedef struct OtherHashAlgAndValue {
    AlgorithmIdentifier_t     hashAlgorithm;
    OtherHashValue_t     hashValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherHashAlgAndValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherHashAlgAndValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherHashAlgAndValue_desc(void);

#ifdef __cplusplus
}
#endif

#endif
