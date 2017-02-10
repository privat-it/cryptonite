/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NumericString_H_
#define    _NumericString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t NumericString_t;    /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t NumericString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NumericString_desc(void);

asn_constr_check_f NumericString_constraint;

#ifdef __cplusplus
}
#endif

#endif
