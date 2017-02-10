/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RevocationValues_H_
#define    _RevocationValues_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherRevVals.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CertificateList;
struct BasicOCSPResponse;

/* RevocationValues */
typedef struct RevocationValues {
    struct crlVals {
        A_SEQUENCE_OF(struct CertificateList) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *crlVals;
    struct ocspVals {
        A_SEQUENCE_OF(struct BasicOCSPResponse) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *ocspVals;
    OtherRevVals_t     otherRevVals;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RevocationValues_t;

/* Implementation */
extern asn_TYPE_descriptor_t RevocationValues_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RevocationValues_desc(void);

#ifdef __cplusplus
}
#endif

#endif
