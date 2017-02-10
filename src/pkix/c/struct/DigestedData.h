/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DigestedData_H_
#define    _DigestedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "DigestAlgorithmIdentifier.h"
#include "EncapsulatedContentInfo.h"
#include "Digest.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DigestedData */
typedef struct DigestedData {
    CMSVersion_t     version;
    DigestAlgorithmIdentifier_t     digestAlgorithm;
    EncapsulatedContentInfo_t     encapContentInfo;
    Digest_t     digest;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DigestedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t DigestedData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DigestedData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
