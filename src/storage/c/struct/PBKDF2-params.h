/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PBKDF2_params_H_
#define    _PBKDF2_params_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PBKDF2-Salt.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct AlgorithmIdentifier;

/* PBKDF2-params */
typedef struct PBKDF2_params {
    PBKDF2_Salt_t     salt;
    INTEGER_t     iterationCount;
    INTEGER_t    *keyLength    /* OPTIONAL */;
    struct AlgorithmIdentifier    *prf    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PBKDF2_params_t;

/* Implementation */
extern asn_TYPE_descriptor_t PBKDF2_params_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PBKDF2_params_desc(void);

#ifdef __cplusplus
}
#endif

#endif
