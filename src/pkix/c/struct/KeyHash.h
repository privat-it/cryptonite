/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyHash_H_
#define    _KeyHash_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyHash */
typedef OCTET_STRING_t     KeyHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyHash_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyHash_desc(void);
asn_struct_free_f KeyHash_free;
asn_struct_print_f KeyHash_print;
asn_constr_check_f KeyHash_constraint;
ber_type_decoder_f KeyHash_decode_ber;
der_type_encoder_f KeyHash_encode_der;
xer_type_decoder_f KeyHash_decode_xer;
xer_type_encoder_f KeyHash_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
