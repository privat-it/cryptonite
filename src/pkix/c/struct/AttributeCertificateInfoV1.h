/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeCertificateInfoV1_H_
#define    _AttributeCertificateInfoV1_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttCertVersionV1.h"
#include "GeneralNames.h"
#include "AlgorithmIdentifier.h"
#include "CertificateSerialNumber.h"
#include "AttCertValidityPeriod.h"
#include "SeqAttributes.h"
#include "UniqueIdentifier.h"
#include "IssuerSerial.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum subject_PR {
    subject_PR_NOTHING,    /* No components present */
    subject_PR_baseCertificateID,
    subject_PR_subjectName
} subject_PR;

/* Forward declarations */
struct Extensions;

/* AttributeCertificateInfoV1 */
typedef struct AttributeCertificateInfoV1 {
    AttCertVersionV1_t    *version    /* DEFAULT 0 */;
    struct subject {
        subject_PR present;
        union AttributeCertificateInfoV1__subject_u {
            IssuerSerial_t     baseCertificateID;
            GeneralNames_t     subjectName;
        } choice;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } subject;
    GeneralNames_t     issuer;
    AlgorithmIdentifier_t     signature;
    CertificateSerialNumber_t     serialNumber;
    AttCertValidityPeriod_t     attCertValidityPeriod;
    SeqAttributes_t     attributes;
    UniqueIdentifier_t    *issuerUniqueID    /* OPTIONAL */;
    struct Extensions    *extensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttributeCertificateInfoV1_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeCertificateInfoV1_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeCertificateInfoV1_desc(void);

#ifdef __cplusplus
}
#endif

#endif
