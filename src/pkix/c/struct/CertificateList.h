/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificateList_H_
#define    _CertificateList_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TBSCertList.h"
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificateList */
typedef struct CertificateList {
    TBSCertList_t     tbsCertList;
    AlgorithmIdentifier_t     signatureAlgorithm;
    BIT_STRING_t     signatureValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertificateList_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificateList_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificateList_desc(void);

#ifdef __cplusplus
}
#endif

#endif
