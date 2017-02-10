/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _GOST28147Params_H_
#define    _GOST28147Params_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GOST28147Params */
typedef struct GOST28147Params {
    OCTET_STRING_t     iv;
    OCTET_STRING_t     dke;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} GOST28147Params_t;

/* Implementation */
extern asn_TYPE_descriptor_t GOST28147Params_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_GOST28147Params_desc(void);

#ifdef __cplusplus
}
#endif

#endif
