/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificateChoices_H_
#define    _CertificateChoices_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Certificate.h"
#include "ExtendedCertificate.h"
#include "AttributeCertificateV1.h"
#include "AttributeCertificateV2.h"
#include "OtherCertificateFormat.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CertificateChoices_PR {
    CertificateChoices_PR_NOTHING,    /* No components present */
    CertificateChoices_PR_certificate,
    CertificateChoices_PR_extendedCertificate,
    CertificateChoices_PR_v1AttrCert,
    CertificateChoices_PR_v2AttrCert,
    CertificateChoices_PR_other
} CertificateChoices_PR;

/* CertificateChoices */
typedef struct CertificateChoices {
    CertificateChoices_PR present;
    union CertificateChoices_u {
        Certificate_t     certificate;
        ExtendedCertificate_t     extendedCertificate;
        AttributeCertificateV1_t     v1AttrCert;
        AttributeCertificateV2_t     v2AttrCert;
        OtherCertificateFormat_t     other;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertificateChoices_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificateChoices_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificateChoices_desc(void);

#ifdef __cplusplus
}
#endif

#endif
