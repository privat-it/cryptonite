/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Extension_H_
#define    _Extension_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "BOOLEAN.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Extension */
typedef struct Extension {
    OBJECT_IDENTIFIER_t     extnID;
    BOOLEAN_t    *critical    /* DEFAULT FALSE */;
    OCTET_STRING_t     extnValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} Extension_t;

/* Implementation */
extern asn_TYPE_descriptor_t Extension_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Extension_desc(void);

#ifdef __cplusplus
}
#endif

#endif
