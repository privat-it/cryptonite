/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NativeEnumerated_H_
#define    _NativeEnumerated_H_

#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This type differs from the standard ENUMERATED in that it is modelled using
 * the fixed machine type (long, int, short), so it can hold only values of
 * limited length. There is no type (i.e., NativeEnumerated_t, any integer type
 * will do).
 * This type may be used when integer range is limited by subtype constraints.
 */

extern asn_TYPE_descriptor_t NativeEnumerated_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NativeEnumerated_desc(void);

xer_type_encoder_f NativeEnumerated_encode_xer;
per_type_decoder_f NativeEnumerated_decode_uper;
per_type_encoder_f NativeEnumerated_encode_uper;

#ifdef __cplusplus
}
#endif

#endif
