/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ExtendedCertificate_H_
#define    _ExtendedCertificate_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ExtendedCertificateInfo.h"
#include "SignatureAlgorithmIdentifier.h"
#include "Signature.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ExtendedCertificate */
typedef struct ExtendedCertificate {
    ExtendedCertificateInfo_t     extendedCertificateInfo;
    SignatureAlgorithmIdentifier_t     signatureAlgorithm;
    Signature_t     signature;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ExtendedCertificate_t;

/* Implementation */
extern asn_TYPE_descriptor_t ExtendedCertificate_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ExtendedCertificate_desc(void);

#ifdef __cplusplus
}
#endif

#endif
