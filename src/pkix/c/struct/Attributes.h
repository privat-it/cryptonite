/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Attributes_H_
#define    _Attributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SET_OF.h"
#include "constr_SET_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attribute;

/* Attributes */
typedef struct Attributes {
    A_SET_OF(struct Attribute) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Attributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t Attributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Attributes_desc(void);

#ifdef __cplusplus
}
#endif

#endif
