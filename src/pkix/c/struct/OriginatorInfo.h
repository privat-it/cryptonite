/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OriginatorInfo_H_
#define    _OriginatorInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CertificateSet;
struct RevocationInfoChoices;

/* OriginatorInfo */
typedef struct OriginatorInfo {
    struct CertificateSet    *certs    /* OPTIONAL */;
    struct RevocationInfoChoices    *crls    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OriginatorInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t OriginatorInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OriginatorInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
