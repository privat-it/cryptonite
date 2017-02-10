/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRevRefType_H_
#define    _OtherRevRefType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRevRefType */
typedef OBJECT_IDENTIFIER_t     OtherRevRefType_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRevRefType_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRevRefType_desc(void);
asn_struct_free_f OtherRevRefType_free;
asn_struct_print_f OtherRevRefType_print;
asn_constr_check_f OtherRevRefType_constraint;
ber_type_decoder_f OtherRevRefType_decode_ber;
der_type_encoder_f OtherRevRefType_encode_der;
xer_type_decoder_f OtherRevRefType_decode_xer;
xer_type_encoder_f OtherRevRefType_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
