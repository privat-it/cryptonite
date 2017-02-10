/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherCertID_H_
#define    _OtherCertID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherHash.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IssuerSerial;

/* OtherCertID */
typedef struct OtherCertID {
    OtherHash_t     otherCertHash;
    struct IssuerSerial    *issuerSerial    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherCertID_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherCertID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherCertID_desc(void);

#ifdef __cplusplus
}
#endif

#endif
