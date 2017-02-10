/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ESSCertIDv2s_H_
#define    _ESSCertIDv2s_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ESSCertIDv2;

/* ESSCertIDv2s */
typedef struct ESSCertIDv2s {
    A_SEQUENCE_OF(struct ESSCertIDv2) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ESSCertIDv2s_t;

/* Implementation */
extern asn_TYPE_descriptor_t ESSCertIDv2s_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ESSCertIDv2s_desc(void);

#ifdef __cplusplus
}
#endif

#endif
