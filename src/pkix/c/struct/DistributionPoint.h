/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DistributionPoint_H_
#define    _DistributionPoint_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ReasonFlags.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DistributionPointName;
struct GeneralNames;

/* DistributionPoint */
typedef struct DistributionPoint {
    struct DistributionPointName    *distributionPoint    /* OPTIONAL */;
    ReasonFlags_t    *reasons    /* OPTIONAL */;
    struct GeneralNames    *crlIssuer    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DistributionPoint_t;

/* Implementation */
extern asn_TYPE_descriptor_t DistributionPoint_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DistributionPoint_desc(void);

#ifdef __cplusplus
}
#endif

#endif
