/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignaturePolicyId_H_
#define    _SignaturePolicyId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SigPolicyId.h"
#include "SigPolicyHash.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SigPolicyQualifierInfo;

/* SignaturePolicyId */
typedef struct SignaturePolicyId {
    SigPolicyId_t     sigPolicyId;
    SigPolicyHash_t     sigPolicyHash;
    struct sigPolicyQualifiers {
        A_SEQUENCE_OF(struct SigPolicyQualifierInfo) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *sigPolicyQualifiers;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SignaturePolicyId_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignaturePolicyId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignaturePolicyId_desc(void);

#ifdef __cplusplus
}
#endif

#endif
