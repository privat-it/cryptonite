/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BinaryField_H_
#define    _BinaryField_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "Pentanomial.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum member_PR {
    member_PR_NOTHING,    /* No components present */
    member_PR_trinomial,
    member_PR_pentanomial
} member_PR;

/* BinaryField */
typedef struct BinaryField {
    INTEGER_t     m;
    struct member {
        member_PR present;
        union BinaryField__member_u {
            INTEGER_t     trinomial;
            Pentanomial_t     pentanomial;
        } choice;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *member;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} BinaryField_t;

/* Implementation */
extern asn_TYPE_descriptor_t BinaryField_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BinaryField_desc(void);

#ifdef __cplusplus
}
#endif

#endif
