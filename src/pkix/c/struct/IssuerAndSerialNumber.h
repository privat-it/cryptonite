/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _IssuerAndSerialNumber_H_
#define    _IssuerAndSerialNumber_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Name.h"
#include "CertificateSerialNumber.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IssuerAndSerialNumber */
typedef struct IssuerAndSerialNumber {
    Name_t     issuer;
    CertificateSerialNumber_t     serialNumber;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} IssuerAndSerialNumber_t;

/* Implementation */
extern asn_TYPE_descriptor_t IssuerAndSerialNumber_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_IssuerAndSerialNumber_desc(void);

#ifdef __cplusplus
}
#endif

#endif
