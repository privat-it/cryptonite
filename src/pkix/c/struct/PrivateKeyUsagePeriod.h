/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PrivateKeyUsagePeriod_H_
#define    _PrivateKeyUsagePeriod_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PrivateKeyUsagePeriod */
typedef struct PrivateKeyUsagePeriod {
    GeneralizedTime_t    *notBefore    /* OPTIONAL */;
    GeneralizedTime_t    *notAfter    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PrivateKeyUsagePeriod_t;

/* Implementation */
extern asn_TYPE_descriptor_t PrivateKeyUsagePeriod_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PrivateKeyUsagePeriod_desc(void);

#ifdef __cplusplus
}
#endif

#endif
