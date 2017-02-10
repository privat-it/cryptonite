/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertID_H_
#define    _CertID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "OCTET_STRING.h"
#include "CertificateSerialNumber.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertID */
typedef struct CertID {
    AlgorithmIdentifier_t     hashAlgorithm;
    OCTET_STRING_t     issuerNameHash;
    OCTET_STRING_t     issuerKeyHash;
    CertificateSerialNumber_t     serialNumber;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertID_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
