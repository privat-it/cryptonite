/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PolicyQualifierInfo_H_
#define    _PolicyQualifierInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PolicyQualifierId.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PolicyQualifierInfo */
typedef struct PolicyQualifierInfo {
    PolicyQualifierId_t     policyQualifierId;
    ANY_t     qualifier;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PolicyQualifierInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t PolicyQualifierInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PolicyQualifierInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
