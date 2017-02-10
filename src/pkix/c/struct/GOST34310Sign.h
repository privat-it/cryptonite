/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _GOST34310Sign_H_
#define    _GOST34310Sign_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GOST34310Sign */
typedef struct GOST34310Sign {
    INTEGER_t     r;
    INTEGER_t     s;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} GOST34310Sign_t;

/* Implementation */
extern asn_TYPE_descriptor_t GOST34310Sign_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_GOST34310Sign_desc(void);

#ifdef __cplusplus
}
#endif

#endif
