/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SeqAttributes_H_
#define    _SeqAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attribute;

/* SeqAttributes */
typedef struct SeqAttributes {
    A_SEQUENCE_OF(struct Attribute) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SeqAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t SeqAttributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SeqAttributes_desc(void);

#ifdef __cplusplus
}
#endif

#endif
