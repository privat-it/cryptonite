/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Accuracy_H_
#define    _Accuracy_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"
#include "NativeInteger.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Accuracy */
typedef struct Accuracy {
    INTEGER_t    *seconds    /* OPTIONAL */;
    long    *millis    /* OPTIONAL */;
    long    *micros    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Accuracy_t;

/* Implementation */
extern asn_TYPE_descriptor_t Accuracy_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Accuracy_desc(void);

#ifdef __cplusplus
}
#endif

#endif
