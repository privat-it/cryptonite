/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Hash_H_
#define    _Hash_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Hash */
typedef OCTET_STRING_t     Hash_t;

/* Implementation */
extern asn_TYPE_descriptor_t Hash_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Hash_desc(void);
asn_struct_free_f Hash_free;
asn_struct_print_f Hash_print;
asn_constr_check_f Hash_constraint;
ber_type_decoder_f Hash_decode_ber;
der_type_encoder_f Hash_encode_der;
xer_type_decoder_f Hash_decode_xer;
xer_type_encoder_f Hash_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
