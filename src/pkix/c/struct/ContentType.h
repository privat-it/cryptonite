/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ContentType_H_
#define    _ContentType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ContentType */
typedef OBJECT_IDENTIFIER_t     ContentType_t;

/* Implementation */
extern asn_TYPE_descriptor_t ContentType_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ContentType_desc(void);
asn_struct_free_f ContentType_free;
asn_struct_print_f ContentType_print;
asn_constr_check_f ContentType_constraint;
ber_type_decoder_f ContentType_decode_ber;
der_type_encoder_f ContentType_encode_der;
xer_type_decoder_f ContentType_decode_xer;
xer_type_encoder_f ContentType_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
