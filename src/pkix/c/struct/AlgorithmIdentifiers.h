/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AlgorithmIdentifiers_H_
#define    _AlgorithmIdentifiers_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SET_OF.h"
#include "constr_SET_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct AlgorithmIdentifier;

/* AlgorithmIdentifiers */
typedef struct AlgorithmIdentifiers {
    A_SET_OF(struct AlgorithmIdentifier) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AlgorithmIdentifiers_t;

/* Implementation */
extern asn_TYPE_descriptor_t AlgorithmIdentifiers_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AlgorithmIdentifiers_desc(void);

#ifdef __cplusplus
}
#endif

#endif
