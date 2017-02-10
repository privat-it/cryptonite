/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeType_H_
#define    _AttributeType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeType */
typedef OBJECT_IDENTIFIER_t     AttributeType_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeType_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeType_desc(void);
asn_struct_free_f AttributeType_free;
asn_struct_print_f AttributeType_print;
asn_constr_check_f AttributeType_constraint;
ber_type_decoder_f AttributeType_decode_ber;
der_type_encoder_f AttributeType_encode_der;
xer_type_decoder_f AttributeType_decode_xer;
xer_type_encoder_f AttributeType_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
