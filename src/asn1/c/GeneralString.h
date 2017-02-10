/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _GeneralString_H_
#define    _GeneralString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t GeneralString_t;    /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t GeneralString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_GeneralString_desc(void);

#ifdef __cplusplus
}
#endif

#endif
