/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CrlID_H_
#define    _CrlID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "IA5String.h"
#include "INTEGER.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CrlID */
typedef struct CrlID {
    IA5String_t    *crlUrl    /* OPTIONAL */;
    INTEGER_t    *crlNum    /* OPTIONAL */;
    GeneralizedTime_t    *crlTime    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CrlID_t;

/* Implementation */
extern asn_TYPE_descriptor_t CrlID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CrlID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
