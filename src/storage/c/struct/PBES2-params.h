/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PBES2_params_H_
#define    _PBES2_params_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PBES2-KDFs.h"
#include "AlgorithmIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PBES2-params */
typedef struct PBES2_params {
    PBES2_KDFs_t     keyDerivationFunc;
    AlgorithmIdentifier_t     encryptionScheme;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PBES2_params_t;

/* Implementation */
extern asn_TYPE_descriptor_t PBES2_params_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PBES2_params_desc(void);

#ifdef __cplusplus
}
#endif

#endif
