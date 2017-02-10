/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignedAttributes_H_
#define    _SignedAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SignedAttributes */
typedef Attributes_t     SignedAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignedAttributes_desc;
extern asn_TYPE_descriptor_t SignedAttributesDer_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignedAttributes_desc(void);
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignedAttributesDer_desc(void);

asn_struct_free_f SignedAttributes_free;
asn_struct_print_f SignedAttributes_print;
asn_constr_check_f SignedAttributes_constraint;
ber_type_decoder_f SignedAttributes_decode_ber;
der_type_encoder_f SignedAttributes_encode_der;
xer_type_decoder_f SignedAttributes_decode_xer;
xer_type_encoder_f SignedAttributes_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
