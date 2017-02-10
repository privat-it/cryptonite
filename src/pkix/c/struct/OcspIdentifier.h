/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OcspIdentifier_H_
#define    _OcspIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ResponderID.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OcspIdentifier */
typedef struct OcspIdentifier {
    ResponderID_t     ocspResponderID;
    GeneralizedTime_t     producedAt;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OcspIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t OcspIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OcspIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
