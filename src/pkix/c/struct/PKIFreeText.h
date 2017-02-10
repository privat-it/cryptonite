/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKIFreeText_H_
#define    _PKIFreeText_H_


#include "asn_application.h"

/* Including external dependencies */
#include "UTF8String.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PKIFreeText */
typedef struct PKIFreeText {
    A_SEQUENCE_OF(UTF8String_t) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PKIFreeText_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIFreeText_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKIFreeText_desc(void);

#ifdef __cplusplus
}
#endif

#endif
