/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _V2Form_H_
#define    _V2Form_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GeneralNames;
struct IssuerSerial;
struct ObjectDigestInfo;

/* V2Form */
typedef struct V2Form {
    struct GeneralNames    *issuerName    /* OPTIONAL */;
    struct IssuerSerial    *baseCertificateID    /* OPTIONAL */;
    struct ObjectDigestInfo    *objectDigestInfo    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} V2Form_t;

/* Implementation */
extern asn_TYPE_descriptor_t V2Form_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_V2Form_desc(void);

#ifdef __cplusplus
}
#endif

#endif
