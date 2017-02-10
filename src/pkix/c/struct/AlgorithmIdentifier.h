/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AlgorithmIdentifier_H_
#define    _AlgorithmIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AlgorithmIdentifier */
typedef struct AlgorithmIdentifier {
    OBJECT_IDENTIFIER_t     algorithm;
    ANY_t    *parameters    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t AlgorithmIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AlgorithmIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
