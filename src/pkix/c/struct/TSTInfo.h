/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TSTInfo_H_
#define    _TSTInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TSVersion.h"
#include "TSAPolicyId.h"
#include "MessageImprint.h"
#include "INTEGER.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Accuracy;
struct GeneralName;
struct Extensions;

/* TSTInfo */
typedef struct TSTInfo {
    TSVersion_t     version;
    TSAPolicyId_t     policy;
    MessageImprint_t     messageImprint;
    INTEGER_t     serialNumber;
    GeneralizedTime_t     genTime;
    struct Accuracy    *accuracy    /* OPTIONAL */;
    INTEGER_t    *nonce    /* OPTIONAL */;
    struct GeneralName    *tsa    /* OPTIONAL */;
    struct Extensions    *extensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TSTInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t TSTInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TSTInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
