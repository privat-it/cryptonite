/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Signature_H_
#define    _Signature_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Certificates;

/* Signature */
typedef struct Signature {
    AlgorithmIdentifier_t     signatureAlgorithm;
    BIT_STRING_t     signature;
    struct Certificates    *certs    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Signature_t;

/* Implementation */
extern asn_TYPE_descriptor_t Signature_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Signature_desc(void);

#ifdef __cplusplus
}
#endif

#endif
