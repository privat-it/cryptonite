/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Pentanomial_H_
#define    _Pentanomial_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pentanomial */
typedef struct Pentanomial {
    INTEGER_t     k;
    INTEGER_t     j;
    INTEGER_t     l;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Pentanomial_t;

/* Implementation */
extern asn_TYPE_descriptor_t Pentanomial_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Pentanomial_desc(void);

#ifdef __cplusplus
}
#endif

#endif
