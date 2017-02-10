/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DigestInfo_H_
#define    _DigestInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DigestAlgorithmIdentifier.h"
#include "Digest.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DigestInfo */
typedef struct DigestInfo {
    DigestAlgorithmIdentifier_t     digestAlgorithm;
    Digest_t     digest;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DigestInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t DigestInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DigestInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
