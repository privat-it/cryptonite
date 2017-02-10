/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Gost34310Params_H_
#define    _Gost34310Params_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Gost34310Params */
typedef struct Gost34310Params {
    struct sequence {
        INTEGER_t     p;
        INTEGER_t     q;
        INTEGER_t     a;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } sequence;
    OCTET_STRING_t    *dke    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Gost34310Params_t;

/* Implementation */
extern asn_TYPE_descriptor_t Gost34310Params_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Gost34310Params_desc(void);

#ifdef __cplusplus
}
#endif

#endif
