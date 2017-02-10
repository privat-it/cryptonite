/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _QCStatement_H_
#define    _QCStatement_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QCStatement */
typedef struct QCStatement {
    OBJECT_IDENTIFIER_t     statementId;
    ANY_t    *statementInfo    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} QCStatement_t;

/* Implementation */
extern asn_TYPE_descriptor_t QCStatement_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_QCStatement_desc(void);

#ifdef __cplusplus
}
#endif

#endif
