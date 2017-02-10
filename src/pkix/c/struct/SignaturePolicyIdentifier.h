/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignaturePolicyIdentifier_H_
#define    _SignaturePolicyIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SignaturePolicyId.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SignaturePolicyIdentifier_PR {
    SignaturePolicyIdentifier_PR_NOTHING,    /* No components present */
    SignaturePolicyIdentifier_PR_signaturePolicyId
} SignaturePolicyIdentifier_PR;

/* SignaturePolicyIdentifier */
typedef struct SignaturePolicyIdentifier {
    SignaturePolicyIdentifier_PR present;
    union SignaturePolicyIdentifier_u {
        SignaturePolicyId_t     signaturePolicyId;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignaturePolicyIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignaturePolicyIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignaturePolicyIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
