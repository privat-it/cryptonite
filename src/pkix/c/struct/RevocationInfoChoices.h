/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RevocationInfoChoices_H_
#define    _RevocationInfoChoices_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SET_OF.h"
#include "constr_SET_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RevocationInfoChoice;

/* RevocationInfoChoices */
typedef struct RevocationInfoChoices {
    A_SET_OF(struct RevocationInfoChoice) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RevocationInfoChoices_t;

/* Implementation */
extern asn_TYPE_descriptor_t RevocationInfoChoices_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RevocationInfoChoices_desc(void);

#ifdef __cplusplus
}
#endif

#endif
