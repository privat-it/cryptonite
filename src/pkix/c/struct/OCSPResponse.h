/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OCSPResponse_H_
#define    _OCSPResponse_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCSPResponseStatus.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ResponseBytes;

/* OCSPResponse */
typedef struct OCSPResponse {
    OCSPResponseStatus_t     responseStatus;
    struct ResponseBytes    *responseBytes    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OCSPResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t OCSPResponse_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OCSPResponse_desc(void);

#ifdef __cplusplus
}
#endif

#endif
