/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DSTU4145Params_H_
#define    _DSTU4145Params_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DSTUEllipticCurve.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DSTU4145Params */
typedef struct DSTU4145Params {
    DSTUEllipticCurve_t     ellipticCurve;
    OCTET_STRING_t    *dke    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DSTU4145Params_t;

/* Implementation */
extern asn_TYPE_descriptor_t DSTU4145Params_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DSTU4145Params_desc(void);

#ifdef __cplusplus
}
#endif

#endif
