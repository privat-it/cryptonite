/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignedData_H_
#define    _SignedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "DigestAlgorithmIdentifiers.h"
#include "EncapsulatedContentInfo.h"
#include "SignerInfos.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CertificateSet;
struct RevocationInfoChoices;

/* SignedData */
typedef struct SignedData {
    CMSVersion_t     version;
    DigestAlgorithmIdentifiers_t     digestAlgorithms;
    EncapsulatedContentInfo_t     encapContentInfo;
    struct CertificateSet    *certificates    /* OPTIONAL */;
    struct RevocationInfoChoices    *crls    /* OPTIONAL */;
    SignerInfos_t     signerInfos;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignedData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignedData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
