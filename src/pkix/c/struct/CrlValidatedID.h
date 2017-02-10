/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CrlValidatedID_H_
#define    _CrlValidatedID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherHash.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CrlIdentifier;

/* CrlValidatedID */
typedef struct CrlValidatedID {
    OtherHash_t     crlHash;
    struct CrlIdentifier    *crlIdentifier    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CrlValidatedID_t;

/* Implementation */
extern asn_TYPE_descriptor_t CrlValidatedID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CrlValidatedID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
