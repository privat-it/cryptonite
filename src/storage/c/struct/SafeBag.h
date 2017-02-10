/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SafeBag_H_
#define    _SafeBag_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attributes;

/* SafeBag */
typedef struct SafeBag {
    OBJECT_IDENTIFIER_t     bagId;
    ANY_t     bagValue;
    struct Attributes    *bagAttributes    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SafeBag_t;

/* Implementation */
extern asn_TYPE_descriptor_t SafeBag_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SafeBag_desc(void);

#ifdef __cplusplus
}
#endif

#endif
