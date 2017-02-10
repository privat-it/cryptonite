/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ResponderID_H_
#define    _ResponderID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Name.h"
#include "KeyHash.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ResponderID_PR {
    ResponderID_PR_NOTHING,    /* No components present */
    ResponderID_PR_byName,
    ResponderID_PR_byKey
} ResponderID_PR;

/* ResponderID */
typedef struct ResponderID {
    ResponderID_PR present;
    union ResponderID_u {
        Name_t     byName;
        KeyHash_t     byKey;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ResponderID_t;

/* Implementation */
extern asn_TYPE_descriptor_t ResponderID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ResponderID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
