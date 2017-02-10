/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    ASN_TYPE_NativeReal_H
#define    ASN_TYPE_NativeReal_H

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This type differs from the standard REAL in that it is modelled using
 * the fixed machine type (double), so it can hold only values of
 * limited precision. There is no explicit type (i.e., NativeReal_t).
 * Use of this type is normally enabled by -fnative-types.
 */

extern asn_TYPE_descriptor_t NativeReal_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NativeReal_desc(void);

asn_struct_free_f NativeReal_free;
asn_struct_print_f NativeReal_print;
ber_type_decoder_f NativeReal_decode_ber;
der_type_encoder_f NativeReal_encode_der;
xer_type_decoder_f NativeReal_decode_xer;
xer_type_encoder_f NativeReal_encode_xer;
per_type_decoder_f NativeReal_decode_uper;
per_type_encoder_f NativeReal_encode_uper;

#ifdef __cplusplus
}
#endif

#endif
