/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKIStatusInfo_H_
#define    _PKIStatusInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PKIStatus.h"
#include "PKIFailureInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PKIFreeText;

/* PKIStatusInfo */
typedef struct PKIStatusInfo {
    PKIStatus_t     status;
    struct PKIFreeText    *statusString    /* OPTIONAL */;
    PKIFailureInfo_t    *failInfo    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PKIStatusInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIStatusInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKIStatusInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
