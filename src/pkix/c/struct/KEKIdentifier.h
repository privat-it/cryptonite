/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KEKIdentifier_H_
#define    _KEKIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "GeneralizedTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OtherKeyAttribute;

/* KEKIdentifier */
typedef struct KEKIdentifier {
    OCTET_STRING_t     keyIdentifier;
    GeneralizedTime_t    *date    /* OPTIONAL */;
    struct OtherKeyAttribute    *other    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} KEKIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t KEKIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KEKIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
