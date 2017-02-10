/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _MonetaryValue_H_
#define    _MonetaryValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Iso4217CurrencyCode.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MonetaryValue */
typedef struct MonetaryValue {
    Iso4217CurrencyCode_t     currency;
    INTEGER_t     amount;
    INTEGER_t     exponent;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} MonetaryValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t MonetaryValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_MonetaryValue_desc(void);

#ifdef __cplusplus
}
#endif

#endif
