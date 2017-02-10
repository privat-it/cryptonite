/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeValueAssertion_H_
#define    _AttributeValueAssertion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttributeTypeAndValue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeValueAssertion */
typedef AttributeTypeAndValue_t     AttributeValueAssertion_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeValueAssertion_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeValueAssertion_desc(void);
asn_struct_free_f AttributeValueAssertion_free;
asn_struct_print_f AttributeValueAssertion_print;
asn_constr_check_f AttributeValueAssertion_constraint;
ber_type_decoder_f AttributeValueAssertion_decode_ber;
der_type_encoder_f AttributeValueAssertion_encode_der;
xer_type_decoder_f AttributeValueAssertion_decode_xer;
xer_type_encoder_f AttributeValueAssertion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
