/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ISO646String_H_
#define    _ISO646String_H_

#include "asn_application.h"
#include "VisibleString.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef VisibleString_t ISO646String_t;    /* Implemented using VisibleString */

extern asn_TYPE_descriptor_t ISO646String_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ISO646String_desc(void);

#ifdef __cplusplus
}
#endif

#endif
