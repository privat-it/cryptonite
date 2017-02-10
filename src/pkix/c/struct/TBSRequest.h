/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TBSRequest_H_
#define    _TBSRequest_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GeneralName;
struct Extensions;
struct Request;

/* TBSRequest */
typedef struct TBSRequest {
    Version_t    *version    /* DEFAULT 0 */;
    struct GeneralName    *requestorName    /* OPTIONAL */;
    struct requestList {
        A_SEQUENCE_OF(struct Request) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } requestList;
    struct Extensions    *requestExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TBSRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t TBSRequest_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TBSRequest_desc(void);

#ifdef __cplusplus
}
#endif

#endif
