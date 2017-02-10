/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BasicOCSPResponse_H_
#define    _BasicOCSPResponse_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ResponseData.h"
#include "AlgorithmIdentifier.h"
#include "BIT_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Certificates;

/* BasicOCSPResponse */
typedef struct BasicOCSPResponse {
    ResponseData_t     tbsResponseData;
    AlgorithmIdentifier_t     signatureAlgorithm;
    BIT_STRING_t     signature;
    struct Certificates    *certs    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} BasicOCSPResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t BasicOCSPResponse_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BasicOCSPResponse_desc(void);

#ifdef __cplusplus
}
#endif

#endif
