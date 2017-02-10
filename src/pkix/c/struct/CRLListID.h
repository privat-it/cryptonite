/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CRLListID_H_
#define    _CRLListID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CrlValidatedID;

/* CRLListID */
typedef struct CRLListID {
    struct crls {
        A_SEQUENCE_OF(struct CrlValidatedID) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } crls;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CRLListID_t;

/* Implementation */
extern asn_TYPE_descriptor_t CRLListID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CRLListID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
