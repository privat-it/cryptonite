/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TBSCertificate_H_
#define    _TBSCertificate_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "CertificateSerialNumber.h"
#include "AlgorithmIdentifier.h"
#include "Name.h"
#include "Validity.h"
#include "SubjectPublicKeyInfo.h"
#include "UniqueIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* TBSCertificate */
typedef struct TBSCertificate {
    Version_t    *version    /* DEFAULT 0 */;
    CertificateSerialNumber_t     serialNumber;
    AlgorithmIdentifier_t     signature;
    Name_t     issuer;
    Validity_t     validity;
    Name_t     subject;
    SubjectPublicKeyInfo_t     subjectPublicKeyInfo;
    UniqueIdentifier_t    *issuerUniqueID    /* OPTIONAL */;
    UniqueIdentifier_t    *subjectUniqueID    /* OPTIONAL */;
    struct Extensions    *extensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TBSCertificate_t;

/* Implementation */
extern asn_TYPE_descriptor_t TBSCertificate_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TBSCertificate_desc(void);

#ifdef __cplusplus
}
#endif

#endif
