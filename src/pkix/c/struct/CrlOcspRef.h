/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CrlOcspRef_H_
#define    _CrlOcspRef_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CRLListID;
struct OcspListID;
struct OtherRevRefs;

/* CrlOcspRef */
typedef struct CrlOcspRef {
    struct CRLListID    *crlids    /* OPTIONAL */;
    struct OcspListID    *ocspids    /* OPTIONAL */;
    struct OtherRevRefs    *otherRev    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CrlOcspRef_t;

/* Implementation */
extern asn_TYPE_descriptor_t CrlOcspRef_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CrlOcspRef_desc(void);

#ifdef __cplusplus
}
#endif

#endif
