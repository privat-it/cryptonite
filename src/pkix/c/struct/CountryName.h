/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CountryName_H_
#define    _CountryName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NumericString.h"
#include "PrintableString.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CountryName_PR {
    CountryName_PR_NOTHING,    /* No components present */
    CountryName_PR_x121_dcc_code,
    CountryName_PR_iso_3166_alpha2_code
} CountryName_PR;

/* CountryName */
typedef struct CountryName {
    CountryName_PR present;
    union CountryName_u {
        NumericString_t     x121_dcc_code;
        PrintableString_t     iso_3166_alpha2_code;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CountryName_t;

/* Implementation */
extern asn_TYPE_descriptor_t CountryName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CountryName_desc(void);

#ifdef __cplusplus
}
#endif

#endif
