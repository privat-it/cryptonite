/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BasicConstraints_H_
#define    _BasicConstraints_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BOOLEAN.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* BasicConstraints */
typedef struct BasicConstraints {
    BOOLEAN_t    *cA    /* DEFAULT FALSE */;
    INTEGER_t    *pathLenConstraint    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} BasicConstraints_t;

/* Implementation */
extern asn_TYPE_descriptor_t BasicConstraints_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BasicConstraints_desc(void);

#ifdef __cplusplus
}
#endif

#endif
