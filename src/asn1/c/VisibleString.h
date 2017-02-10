/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _VisibleString_H_
#define    _VisibleString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t VisibleString_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t VisibleString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_VisibleString_desc(void);

asn_constr_check_f VisibleString_constraint;

#ifdef __cplusplus
}
#endif

#endif
