/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ExtendedCertificateInfo_H_
#define    _ExtendedCertificateInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "Certificate.h"
#include "UnauthAttributes.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ExtendedCertificateInfo */
typedef struct ExtendedCertificateInfo {
    CMSVersion_t     version;
    Certificate_t     certificate;
    UnauthAttributes_t     attributes;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ExtendedCertificateInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t ExtendedCertificateInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ExtendedCertificateInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
