/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _X121Address_H_
#define    _X121Address_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NumericString.h"

#ifdef __cplusplus
extern "C" {
#endif

/* X121Address */
typedef NumericString_t     X121Address_t;

/* Implementation */
extern asn_TYPE_descriptor_t X121Address_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_X121Address_desc(void);
asn_struct_free_f X121Address_free;
asn_struct_print_f X121Address_print;
asn_constr_check_f X121Address_constraint;
ber_type_decoder_f X121Address_decode_ber;
der_type_encoder_f X121Address_encode_der;
xer_type_decoder_f X121Address_decode_xer;
xer_type_encoder_f X121Address_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
