/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UnsignedAttributes_H_
#define    _UnsignedAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UnsignedAttributes */
typedef Attributes_t     UnsignedAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t UnsignedAttributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UnsignedAttributes_desc(void);
asn_struct_free_f UnsignedAttributes_free;
asn_struct_print_f UnsignedAttributes_print;
asn_constr_check_f UnsignedAttributes_constraint;
ber_type_decoder_f UnsignedAttributes_decode_ber;
der_type_encoder_f UnsignedAttributes_encode_der;
xer_type_decoder_f UnsignedAttributes_decode_xer;
xer_type_encoder_f UnsignedAttributes_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
