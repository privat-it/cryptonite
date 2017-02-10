/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyAgreeRecipientIdentifier_H_
#define    _KeyAgreeRecipientIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IssuerAndSerialNumber.h"
#include "RecipientKeyIdentifier.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum KeyAgreeRecipientIdentifier_PR {
    KeyAgreeRecipientIdentifier_PR_NOTHING,    /* No components present */
    KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber,
    KeyAgreeRecipientIdentifier_PR_rKeyId
} KeyAgreeRecipientIdentifier_PR;

/* KeyAgreeRecipientIdentifier */
typedef struct KeyAgreeRecipientIdentifier {
    KeyAgreeRecipientIdentifier_PR present;
    union KeyAgreeRecipientIdentifier_u {
        IssuerAndSerialNumber_t     issuerAndSerialNumber;
        RecipientKeyIdentifier_t     rKeyId;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} KeyAgreeRecipientIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyAgreeRecipientIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyAgreeRecipientIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
