/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RecipientIdentifier_H_
#define    _RecipientIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "SubjectKeyIdentifier.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RecipientIdentifier_PR {
    RecipientIdentifier_PR_NOTHING,    /* No components present */
    RecipientIdentifier_PR_issuerAndSerialNumber,
    RecipientIdentifier_PR_subjectKeyIdentifier
} RecipientIdentifier_PR;

/* RecipientIdentifier */
typedef struct RecipientIdentifier {
    RecipientIdentifier_PR present;
    union RecipientIdentifier_u {
        IssuerAndSerialNumber_t     issuerAndSerialNumber;
        SubjectKeyIdentifier_t     subjectKeyIdentifier;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RecipientIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t RecipientIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RecipientIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
