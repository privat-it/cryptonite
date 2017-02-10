/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SigPolicyQualifierInfo_H_
#define    _SigPolicyQualifierInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SigPolicyQualifierId.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SigPolicyQualifierInfo */
typedef struct SigPolicyQualifierInfo {
    SigPolicyQualifierId_t     sigPolicyQualifierId;
    ANY_t     sigQualifier;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SigPolicyQualifierInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigPolicyQualifierInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SigPolicyQualifierInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
