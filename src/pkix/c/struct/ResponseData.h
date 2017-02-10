/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ResponseData_H_
#define    _ResponseData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "ResponderID.h"
#include "GeneralizedTime.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;
struct SingleResponse;

/* ResponseData */
typedef struct ResponseData {
    Version_t    *version    /* DEFAULT 0 */;
    ResponderID_t     responderID;
    GeneralizedTime_t     producedAt;
    struct responses {
        A_SEQUENCE_OF(struct SingleResponse) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } responses;
    struct Extensions    *responseExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ResponseData_t;

/* Implementation */
extern asn_TYPE_descriptor_t ResponseData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ResponseData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
