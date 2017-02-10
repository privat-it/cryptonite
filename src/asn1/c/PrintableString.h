/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PrintableString_H_
#define    _PrintableString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t PrintableString_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t PrintableString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PrintableString_desc(void);

asn_constr_check_f PrintableString_constraint;

#ifdef __cplusplus
}
#endif

#endif
