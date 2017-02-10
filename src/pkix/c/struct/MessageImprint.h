/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _MessageImprint_H_
#define    _MessageImprint_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MessageImprint */
typedef struct MessageImprint {
    AlgorithmIdentifier_t     hashAlgorithm;
    OCTET_STRING_t     hashedMessage;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} MessageImprint_t;

/* Implementation */
extern asn_TYPE_descriptor_t MessageImprint_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_MessageImprint_desc(void);

#ifdef __cplusplus
}
#endif

#endif
