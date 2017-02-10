/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherCertificateFormat_H_
#define    _OtherCertificateFormat_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherCertificateFormat */
typedef struct OtherCertificateFormat {
    OBJECT_IDENTIFIER_t     otherCertFormat;
    ANY_t     otherCert;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherCertificateFormat_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherCertificateFormat_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherCertificateFormat_desc(void);

#ifdef __cplusplus
}
#endif

#endif
