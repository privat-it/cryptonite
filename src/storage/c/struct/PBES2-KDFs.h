/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PBES2_KDFs_H_
#define    _PBES2_KDFs_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "PBKDF2-params.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PBES2-KDFs */
typedef struct PBES2_KDFs {
    OBJECT_IDENTIFIER_t     algorithm;
    PBKDF2_params_t     parameters;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PBES2_KDFs_t;

/* Implementation */
extern asn_TYPE_descriptor_t PBES2_KDFs_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PBES2_KDFs_desc(void);

#ifdef __cplusplus
}
#endif

#endif
