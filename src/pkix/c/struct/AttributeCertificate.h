/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeCertificate_H_
#define    _AttributeCertificate_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttributeCertificateInfo.h"
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeCertificate */
typedef struct AttributeCertificate {
    AttributeCertificateInfo_t     acinfo;
    AlgorithmIdentifier_t     signatureAlgorithm;
    BIT_STRING_t     signatureValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttributeCertificate_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeCertificate_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeCertificate_desc(void);

#ifdef __cplusplus
}
#endif

#endif
