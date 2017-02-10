/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ResponseBytes_H_
#define    _ResponseBytes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ResponseBytes */
typedef struct ResponseBytes {
    OBJECT_IDENTIFIER_t     responseType;
    OCTET_STRING_t     response;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ResponseBytes_t;

/* Implementation */
extern asn_TYPE_descriptor_t ResponseBytes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ResponseBytes_desc(void);

#ifdef __cplusplus
}
#endif

#endif
