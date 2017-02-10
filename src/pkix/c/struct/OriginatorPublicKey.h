/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OriginatorPublicKey_H_
#define    _OriginatorPublicKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OriginatorPublicKey */
typedef struct OriginatorPublicKey {
    AlgorithmIdentifier_t     algorithm;
    BIT_STRING_t     publicKey;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OriginatorPublicKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t OriginatorPublicKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OriginatorPublicKey_desc(void);

#ifdef __cplusplus
}
#endif

#endif
