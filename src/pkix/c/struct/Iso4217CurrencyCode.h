/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Iso4217CurrencyCode_H_
#define    _Iso4217CurrencyCode_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"
#include "NativeInteger.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Iso4217CurrencyCode_PR {
    Iso4217CurrencyCode_PR_NOTHING,    /* No components present */
    Iso4217CurrencyCode_PR_alphabetic,
    Iso4217CurrencyCode_PR_numeric
} Iso4217CurrencyCode_PR;

/* Iso4217CurrencyCode */
typedef struct Iso4217CurrencyCode {
    Iso4217CurrencyCode_PR present;
    union Iso4217CurrencyCode_u {
        PrintableString_t     alphabetic;
        long     numeric;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Iso4217CurrencyCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t Iso4217CurrencyCode_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Iso4217CurrencyCode_desc(void);

#ifdef __cplusplus
}
#endif

#endif
