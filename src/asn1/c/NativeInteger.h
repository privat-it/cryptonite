/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NativeInteger_H_
#define    _NativeInteger_H_

#include "asn_application.h"
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This type differs from the standard INTEGER in that it is modelled using
 * the fixed machine type (long, int, short), so it can hold only values of
 * limited length. There is no type (i.e., NativeInteger_t, any integer type
 * will do).
 * This type may be used when integer range is limited by subtype constraints.
 */

extern asn_TYPE_descriptor_t NativeInteger_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NativeInteger_desc(void);

asn_struct_free_f NativeInteger_free;
asn_struct_print_f NativeInteger_print;
ber_type_decoder_f NativeInteger_decode_ber;
der_type_encoder_f NativeInteger_encode_der;
xer_type_decoder_f NativeInteger_decode_xer;
xer_type_encoder_f NativeInteger_encode_xer;
per_type_decoder_f NativeInteger_decode_uper;
per_type_encoder_f NativeInteger_encode_uper;

#ifdef __cplusplus
}
#endif

#endif
