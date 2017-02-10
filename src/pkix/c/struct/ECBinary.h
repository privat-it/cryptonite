/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ECBinary_H_
#define    _ECBinary_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "BinaryField.h"
#include "NativeInteger.h"
#include "OCTET_STRING.h"
#include "INTEGER.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ECBinary */
typedef struct ECBinary {
    Version_t    *version    /* DEFAULT 0 */;
    BinaryField_t     f;
    long     a;
    OCTET_STRING_t     b;
    INTEGER_t     n;
    OCTET_STRING_t     bp;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} ECBinary_t;

/* Implementation */
extern asn_TYPE_descriptor_t ECBinary_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ECBinary_desc(void);

#ifdef __cplusplus
}
#endif

#endif
