/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PolicyQualifiers_H_
#define    _PolicyQualifiers_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PolicyQualifierInfo;

/* PolicyQualifiers */
typedef struct PolicyQualifiers {
    A_SEQUENCE_OF(struct PolicyQualifierInfo) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PolicyQualifiers_t;

/* Implementation */
extern asn_TYPE_descriptor_t PolicyQualifiers_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PolicyQualifiers_desc(void);

#ifdef __cplusplus
}
#endif

#endif
