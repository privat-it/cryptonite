/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignerIdentifierIm_H_
#define    _SignerIdentifierIm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "SubjectKeyIdentifier.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SignerIdentifierIm_PR {
    SignerIdentifierIm_PR_NOTHING,    /* No components present */
    SignerIdentifierIm_PR_issuerAndSerialNumber,
    SignerIdentifierIm_PR_subjectKeyIdentifier
} SignerIdentifierIm_PR;

/* SignerIdentifierIm */
typedef struct SignerIdentifierIm {
    SignerIdentifierIm_PR present;
    union SignerIdentifierIm_u {
        IssuerAndSerialNumber_t     issuerAndSerialNumber;
        SubjectKeyIdentifier_t     subjectKeyIdentifier;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignerIdentifierIm_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignerIdentifierIm_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignerIdentifierIm_desc(void);

#ifdef __cplusplus
}
#endif

#endif
