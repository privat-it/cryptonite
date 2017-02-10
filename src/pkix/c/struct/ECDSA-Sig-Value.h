/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ECDSA_Sig_Value_H_
#define    _ECDSA_Sig_Value_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ECDSA-Sig-Value */
typedef struct ECDSA_Sig_Value {
    INTEGER_t     r;
    INTEGER_t     s;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ECDSA_Sig_Value_t;

/* Implementation */
extern asn_TYPE_descriptor_t ECDSA_Sig_Value_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ECDSA_Sig_Value_desc(void);

#ifdef __cplusplus
}
#endif

#endif
