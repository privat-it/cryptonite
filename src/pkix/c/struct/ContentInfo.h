/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ContentInfo_H_
#define    _ContentInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ContentType.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ContentInfo */
typedef struct ContentInfo {
    ContentType_t     contentType;
    ANY_t     content;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ContentInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t ContentInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ContentInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
