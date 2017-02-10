/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _IssuerSerial_H_
#define    _IssuerSerial_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralNames.h"
#include "CertificateSerialNumber.h"
#include "UniqueIdentifier.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IssuerSerial */
typedef struct IssuerSerial {
    GeneralNames_t     issuer;
    CertificateSerialNumber_t     serialNumber;
    UniqueIdentifier_t    *issuerUID    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} IssuerSerial_t;

/* Implementation */
extern asn_TYPE_descriptor_t IssuerSerial_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_IssuerSerial_desc(void);

#ifdef __cplusplus
}
#endif

#endif
