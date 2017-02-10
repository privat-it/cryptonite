/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeValue_H_
#define    _AttributeValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ANY.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeValue */
typedef ANY_t     AttributeValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeValue_desc(void);
asn_struct_free_f AttributeValue_free;
asn_struct_print_f AttributeValue_print;
asn_constr_check_f AttributeValue_constraint;
ber_type_decoder_f AttributeValue_decode_ber;
der_type_encoder_f AttributeValue_encode_der;
xer_type_decoder_f AttributeValue_decode_xer;
xer_type_encoder_f AttributeValue_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
