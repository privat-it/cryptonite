/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignerIdentifierEx_H_
#define    _SignerIdentifierEx_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "SubjectKeyIdentifier.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SignerIdentifierEx_PR {
    SignerIdentifierEx_PR_NOTHING,    /* No components present */
    SignerIdentifierEx_PR_issuerAndSerialNumber,
    SignerIdentifierEx_PR_subjectKeyIdentifier
} SignerIdentifierEx_PR;

/* SignerIdentifierEx */
typedef struct SignerIdentifierEx {
    SignerIdentifierEx_PR present;
    union SignerIdentifierEx_u {
        IssuerAndSerialNumber_t     issuerAndSerialNumber;
        SubjectKeyIdentifier_t     subjectKeyIdentifier;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignerIdentifierEx_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignerIdentifierEx_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignerIdentifierEx_desc(void);

#ifdef __cplusplus
}
#endif

#endif
