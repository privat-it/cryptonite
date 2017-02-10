/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeCertificateV1_H_
#define    _AttributeCertificateV1_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttributeCertificateInfoV1.h"
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeCertificateV1 */
typedef struct AttributeCertificateV1 {
    AttributeCertificateInfoV1_t     acInfo;
    AlgorithmIdentifier_t     signatureAlgorithm;
    BIT_STRING_t     signature;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttributeCertificateV1_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeCertificateV1_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeCertificateV1_desc(void);

#ifdef __cplusplus
}
#endif

#endif
