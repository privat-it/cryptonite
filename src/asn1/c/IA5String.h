/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _IA5String_H_
#define    _IA5String_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t IA5String_t;  /* Implemented via OCTET STRING */

/*
 * IA5String ASN.1 type definition.
 */
extern asn_TYPE_descriptor_t IA5String_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_IA5String_desc(void);

asn_constr_check_f IA5String_constraint;

#ifdef __cplusplus
}
#endif

#endif
