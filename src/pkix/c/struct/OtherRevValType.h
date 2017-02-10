/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRevValType_H_
#define    _OtherRevValType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRevValType */
typedef OBJECT_IDENTIFIER_t     OtherRevValType_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRevValType_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRevValType_desc(void);
asn_struct_free_f OtherRevValType_free;
asn_struct_print_f OtherRevValType_print;
asn_constr_check_f OtherRevValType_constraint;
ber_type_decoder_f OtherRevValType_decode_ber;
der_type_encoder_f OtherRevValType_encode_der;
xer_type_decoder_f OtherRevValType_decode_xer;
xer_type_encoder_f OtherRevValType_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
