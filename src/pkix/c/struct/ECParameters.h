/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ECParameters_H_
#define    _ECParameters_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ECParameters_PR {
    ECParameters_PR_NOTHING,    /* No components present */
    ECParameters_PR_namedCurve
} ECParameters_PR;

/* ECParameters */
typedef struct ECParameters {
    ECParameters_PR present;
    union ECParameters_u {
        OBJECT_IDENTIFIER_t     namedCurve;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ECParameters_t;

/* Implementation */
extern asn_TYPE_descriptor_t ECParameters_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ECParameters_desc(void);

#ifdef __cplusplus
}
#endif

#endif
