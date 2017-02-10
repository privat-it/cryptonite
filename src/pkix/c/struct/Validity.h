/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Validity_H_
#define    _Validity_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PKIXTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Validity */
typedef struct Validity {
    PKIXTime_t     notBefore;
    PKIXTime_t     notAfter;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Validity_t;

/* Implementation */
extern asn_TYPE_descriptor_t Validity_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Validity_desc(void);

#ifdef __cplusplus
}
#endif

#endif
