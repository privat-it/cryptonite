/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _T61String_H_
#define    _T61String_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t T61String_t;    /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t T61String_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_T61String_desc(void);

#ifdef __cplusplus
}
#endif

#endif
