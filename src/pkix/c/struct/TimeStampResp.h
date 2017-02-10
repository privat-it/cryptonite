/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TimeStampResp_H_
#define    _TimeStampResp_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PKIStatusInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ContentInfo;

/* TimeStampResp */
typedef struct TimeStampResp {
    PKIStatusInfo_t     status;
    struct ContentInfo    *timeStampToken    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TimeStampResp_t;

/* Implementation */
extern asn_TYPE_descriptor_t TimeStampResp_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TimeStampResp_desc(void);

#ifdef __cplusplus
}
#endif

#endif
