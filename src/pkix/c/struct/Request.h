/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Request_H_
#define    _Request_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CertID.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* Request */
typedef struct Request {
    CertID_t     reqCert;
    struct Extensions    *singleRequestExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Request_t;

/* Implementation */
extern asn_TYPE_descriptor_t Request_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Request_desc(void);

#ifdef __cplusplus
}
#endif

#endif
