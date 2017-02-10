/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OcspResponsesID_H_
#define    _OcspResponsesID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OcspIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OtherHash;

/* OcspResponsesID */
typedef struct OcspResponsesID {
    OcspIdentifier_t     ocspIdentifier;
    struct OtherHash    *ocspRepHash    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OcspResponsesID_t;

/* Implementation */
extern asn_TYPE_descriptor_t OcspResponsesID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OcspResponsesID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
