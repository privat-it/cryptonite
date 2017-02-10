/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EncapsulatedContentInfo_H_
#define    _EncapsulatedContentInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ContentType.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EncapsulatedContentInfo */
typedef struct EncapsulatedContentInfo {
    ContentType_t     eContentType;
    OCTET_STRING_t    *eContent    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EncapsulatedContentInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t EncapsulatedContentInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EncapsulatedContentInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
