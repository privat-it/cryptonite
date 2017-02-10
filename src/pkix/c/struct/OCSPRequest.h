/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OCSPRequest_H_
#define    _OCSPRequest_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TBSRequest.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Signature;

/* OCSPRequest */
typedef struct OCSPRequest {
    TBSRequest_t     tbsRequest;
    struct Signature    *optionalSignature    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OCSPRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t OCSPRequest_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OCSPRequest_desc(void);

#ifdef __cplusplus
}
#endif

#endif
