/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CrlIdentifier_H_
#define    _CrlIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Name.h"
#include "UTCTime.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CrlIdentifier */
typedef struct CrlIdentifier {
    Name_t     crlissuer;
    UTCTime_t     crlIssuedTime;
    INTEGER_t    *crlNumber    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CrlIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t CrlIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CrlIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
