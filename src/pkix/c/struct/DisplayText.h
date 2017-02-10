/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DisplayText_H_
#define    _DisplayText_H_


#include "asn_application.h"

/* Including external dependencies */
#include "VisibleString.h"
#include "BMPString.h"
#include "UTF8String.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DisplayText_PR {
    DisplayText_PR_NOTHING,    /* No components present */
    DisplayText_PR_visibleString,
    DisplayText_PR_bmpString,
    DisplayText_PR_utf8String
} DisplayText_PR;

/* DisplayText */
typedef struct DisplayText {
    DisplayText_PR present;
    union DisplayText_u {
        VisibleString_t     visibleString;
        BMPString_t     bmpString;
        UTF8String_t     utf8String;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DisplayText_t;

/* Implementation */
extern asn_TYPE_descriptor_t DisplayText_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DisplayText_desc(void);

#ifdef __cplusplus
}
#endif

#endif
