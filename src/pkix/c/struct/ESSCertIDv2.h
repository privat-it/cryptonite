/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ESSCertIDv2_H_
#define    _ESSCertIDv2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "Hash.h"
#include "IssuerSerial.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ESSCertIDv2 */
typedef struct ESSCertIDv2 {
    AlgorithmIdentifier_t     hashAlgorithm;
    Hash_t     certHash;
    IssuerSerial_t     issuerSerial;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ESSCertIDv2_t;

/* Implementation */
extern asn_TYPE_descriptor_t ESSCertIDv2_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ESSCertIDv2_desc(void);

#ifdef __cplusplus
}
#endif

#endif
