/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BOOLEAN_H_
#define    _BOOLEAN_H_

#include "asn_application.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The underlying integer may contain various values, but everything
 * non-zero is capped to 0xff by the DER encoder. The BER decoder may
 * yield non-zero values different from 1, beware.
 */
typedef int BOOLEAN_t;

extern asn_TYPE_descriptor_t BOOLEAN_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BOOLEAN_desc(void);

asn_struct_free_f BOOLEAN_free;
asn_struct_print_f BOOLEAN_print;
ber_type_decoder_f BOOLEAN_decode_ber;
der_type_encoder_f BOOLEAN_encode_der;
xer_type_decoder_f BOOLEAN_decode_xer;
xer_type_encoder_f BOOLEAN_encode_xer;
per_type_decoder_f BOOLEAN_decode_uper;
per_type_encoder_f BOOLEAN_encode_uper;

#ifdef __cplusplus
}
#endif

#endif
