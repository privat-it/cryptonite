/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DSTUEllipticCurve_H_
#define    _DSTUEllipticCurve_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ECBinary.h"
#include "OBJECT_IDENTIFIER.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DSTUEllipticCurve_PR {
    DSTUEllipticCurve_PR_NOTHING,    /* No components present */
    DSTUEllipticCurve_PR_ecbinary,
    DSTUEllipticCurve_PR_namedCurve
} DSTUEllipticCurve_PR;

/* DSTUEllipticCurve */
typedef struct DSTUEllipticCurve {
    DSTUEllipticCurve_PR present;
    union DSTUEllipticCurve_u {
        ECBinary_t     ecbinary;
        OBJECT_IDENTIFIER_t     namedCurve;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} DSTUEllipticCurve_t;

/* Implementation */
extern asn_TYPE_descriptor_t DSTUEllipticCurve_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DSTUEllipticCurve_desc(void);

#ifdef __cplusplus
}
#endif

#endif
