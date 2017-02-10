/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TimeStampReq_H_
#define    _TimeStampReq_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TSVersion.h"
#include "MessageImprint.h"
#include "TSAPolicyId.h"
#include "INTEGER.h"
#include "BOOLEAN.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* TimeStampReq */
typedef struct TimeStampReq {
    TSVersion_t     version;
    MessageImprint_t     messageImprint;
    TSAPolicyId_t    *reqPolicy    /* OPTIONAL */;
    INTEGER_t    *nonce    /* OPTIONAL */;
    BOOLEAN_t    *certReq    /* DEFAULT FALSE */;
    struct Extensions    *extensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TimeStampReq_t;

/* Implementation */
extern asn_TYPE_descriptor_t TimeStampReq_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TimeStampReq_desc(void);

#ifdef __cplusplus
}
#endif

#endif
