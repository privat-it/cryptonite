/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CRLDistributionPoints_H_
#define    _CRLDistributionPoints_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DistributionPoint;

/* CRLDistributionPoints */
typedef struct CRLDistributionPoints {
    A_SEQUENCE_OF(struct DistributionPoint) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CRLDistributionPoints_t;

/* Implementation */
extern asn_TYPE_descriptor_t CRLDistributionPoints_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CRLDistributionPoints_desc(void);

#ifdef __cplusplus
}
#endif

#endif
