/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SecretBag_H_
#define    _SecretBag_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SecretBag */
typedef struct SecretBag {
    OBJECT_IDENTIFIER_t     secretTypeId;
    ANY_t     secretValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SecretBag_t;

/* Implementation */
extern asn_TYPE_descriptor_t SecretBag_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SecretBag_desc(void);

#ifdef __cplusplus
}
#endif

#endif
