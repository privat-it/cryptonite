/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeCertificateInfo_H_
#define    _AttributeCertificateInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttCertVersion.h"
#include "Holder.h"
#include "AttCertIssuer.h"
#include "AlgorithmIdentifier.h"
#include "CertificateSerialNumber.h"
#include "AttCertValidityPeriod.h"
#include "SeqAttributes.h"
#include "UniqueIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* AttributeCertificateInfo */
typedef struct AttributeCertificateInfo {
    AttCertVersion_t     version;
    Holder_t     holder;
    AttCertIssuer_t     issuer;
    AlgorithmIdentifier_t     signature;
    CertificateSerialNumber_t     serialNumber;
    AttCertValidityPeriod_t     attrCertValidityPeriod;
    SeqAttributes_t     attributes;
    UniqueIdentifier_t    *issuerUniqueID    /* OPTIONAL */;
    struct Extensions    *extensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttributeCertificateInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeCertificateInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeCertificateInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
