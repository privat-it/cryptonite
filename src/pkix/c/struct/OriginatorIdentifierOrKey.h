/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OriginatorIdentifierOrKey_H_
#define    _OriginatorIdentifierOrKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "SubjectKeyIdentifier.h"
#include "OriginatorPublicKey.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OriginatorIdentifierOrKey_PR {
    OriginatorIdentifierOrKey_PR_NOTHING,    /* No components present */
    OriginatorIdentifierOrKey_PR_issuerAndSerialNumber,
    OriginatorIdentifierOrKey_PR_subjectKeyIdentifier,
    OriginatorIdentifierOrKey_PR_originatorKey
} OriginatorIdentifierOrKey_PR;

/* OriginatorIdentifierOrKey */
typedef struct OriginatorIdentifierOrKey {
    OriginatorIdentifierOrKey_PR present;
    union OriginatorIdentifierOrKey_u {
        IssuerAndSerialNumber_t     issuerAndSerialNumber;
        SubjectKeyIdentifier_t     subjectKeyIdentifier;
        OriginatorPublicKey_t     originatorKey;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OriginatorIdentifierOrKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t OriginatorIdentifierOrKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OriginatorIdentifierOrKey_desc(void);

#ifdef __cplusplus
}
#endif

#endif
