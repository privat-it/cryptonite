/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKIXTime_H_
#define    _PKIXTime_H_


#include "asn_application.h"

/* Including external dependencies */
#include "UTCTime.h"
#include "GeneralizedTime.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PKIXTime_PR {
    PKIXTime_PR_NOTHING,    /* No components present */
    PKIXTime_PR_utcTime,
    PKIXTime_PR_generalTime
} PKIXTime_PR;

/* PKIXTime */
typedef struct PKIXTime {
    PKIXTime_PR present;
    union PKIXTime_u {
        UTCTime_t     utcTime;
        GeneralizedTime_t     generalTime;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PKIXTime_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIXTime_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKIXTime_desc(void);

#ifdef __cplusplus
}
#endif

#endif
