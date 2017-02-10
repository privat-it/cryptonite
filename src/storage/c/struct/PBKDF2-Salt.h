/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PBKDF2_Salt_H_
#define    _PBKDF2_Salt_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "AlgorithmIdentifier.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PBKDF2_Salt_PR {
    PBKDF2_Salt_PR_NOTHING,    /* No components present */
    PBKDF2_Salt_PR_specified,
    PBKDF2_Salt_PR_otherSource
} PBKDF2_Salt_PR;

/* PBKDF2-Salt */
typedef struct PBKDF2_Salt {
    PBKDF2_Salt_PR present;
    union PBKDF2_Salt_u {
        OCTET_STRING_t     specified;
        AlgorithmIdentifier_t     otherSource;
    } choice;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PBKDF2_Salt_t;

/* Implementation */
extern asn_TYPE_descriptor_t PBKDF2_Salt_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PBKDF2_Salt_desc(void);

#ifdef __cplusplus
}
#endif

#endif
