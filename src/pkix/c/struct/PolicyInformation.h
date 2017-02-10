/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PolicyInformation_H_
#define    _PolicyInformation_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CertPolicyId.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PolicyQualifierInfo;

/* PolicyInformation */
typedef struct PolicyInformation {
    CertPolicyId_t     policyIdentifier;
    struct policyQualifiers {
        A_SEQUENCE_OF(struct PolicyQualifierInfo) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *policyQualifiers;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PolicyInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t PolicyInformation_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PolicyInformation_desc(void);

#ifdef __cplusplus
}
#endif

#endif
