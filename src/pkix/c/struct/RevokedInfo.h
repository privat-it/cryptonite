/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RevokedInfo_H_
#define    _RevokedInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralizedTime.h"
#include "CRLReason.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RevokedInfo */
typedef struct RevokedInfo {
    GeneralizedTime_t     revocationTime;
    CRLReason_t    *revocationReason    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RevokedInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t RevokedInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RevokedInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
