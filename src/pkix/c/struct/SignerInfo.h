/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignerInfo_H_
#define    _SignerInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "SignerIdentifier.h"
#include "DigestAlgorithmIdentifier.h"
#include "SignatureAlgorithmIdentifier.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attributes;

/* SignerInfo */
typedef struct SignerInfo {
    CMSVersion_t     version;
    SignerIdentifier_t     sid;
    DigestAlgorithmIdentifier_t     digestAlgorithm;
    struct Attributes    *signedAttrs    /* OPTIONAL */;
    SignatureAlgorithmIdentifier_t     signatureAlgorithm;
    OCTET_STRING_t     signature;
    struct Attributes    *unsignedAttrs    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignerInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignerInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignerInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
