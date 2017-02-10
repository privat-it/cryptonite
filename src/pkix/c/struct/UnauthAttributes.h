/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UnauthAttributes_H_
#define    _UnauthAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UnauthAttributes */
typedef Attributes_t     UnauthAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t UnauthAttributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UnauthAttributes_desc(void);
asn_struct_free_f UnauthAttributes_free;
asn_struct_print_f UnauthAttributes_print;
asn_constr_check_f UnauthAttributes_constraint;
ber_type_decoder_f UnauthAttributes_decode_ber;
der_type_encoder_f UnauthAttributes_encode_der;
xer_type_decoder_f UnauthAttributes_decode_xer;
xer_type_encoder_f UnauthAttributes_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
