/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ObjectDescriptor_H_
#define    _ObjectDescriptor_H_

#include "GraphicString.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef GraphicString_t ObjectDescriptor_t;  /* Implemented via GraphicString */

extern asn_TYPE_descriptor_t ObjectDescriptor_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_asn_ObjectDescriptor_desc(void);

#ifdef __cplusplus
}
#endif

#endif
