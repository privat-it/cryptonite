/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ExtendedKeyUsage_H_
#define    _ExtendedKeyUsage_H_


#include "asn_application.h"

/* Including external dependencies */
#include "KeyPurposeId.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ExtendedKeyUsage */
typedef struct ExtendedKeyUsage {
    A_SEQUENCE_OF(KeyPurposeId_t) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ExtendedKeyUsage_t;

/* Implementation */
extern asn_TYPE_descriptor_t ExtendedKeyUsage_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ExtendedKeyUsage_desc(void);

#ifdef __cplusplus
}
#endif

#endif
