/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttCertValidityPeriod_H_
#define    _AttCertValidityPeriod_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttCertValidityPeriod */
typedef struct AttCertValidityPeriod {
    GeneralizedTime_t     notBeforeTime;
    GeneralizedTime_t     notAfterTime;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AttCertValidityPeriod_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttCertValidityPeriod_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttCertValidityPeriod_desc(void);

#ifdef __cplusplus
}
#endif

#endif
