/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OcspListID_H_
#define    _OcspListID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OcspResponsesID;

/* OcspListID */
typedef struct OcspListID {
    struct ocspResponses {
        A_SEQUENCE_OF(struct OcspResponsesID) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } ocspResponses;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OcspListID_t;

/* Implementation */
extern asn_TYPE_descriptor_t OcspListID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OcspListID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
