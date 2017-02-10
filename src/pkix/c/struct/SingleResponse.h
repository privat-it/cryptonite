/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SingleResponse_H_
#define    _SingleResponse_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CertID.h"
#include "CertStatus.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* SingleResponse */
typedef struct SingleResponse {
    CertID_t     certID;
    CertStatus_t     certStatus;
    GeneralizedTime_t     thisUpdate;
    GeneralizedTime_t    *nextUpdate    /* OPTIONAL */;
    struct Extensions    *singleExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SingleResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t SingleResponse_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SingleResponse_desc(void);

#ifdef __cplusplus
}
#endif

#endif
