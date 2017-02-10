/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherHashValue_H_
#define    _OtherHashValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherHashValue */
typedef OCTET_STRING_t     OtherHashValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherHashValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherHashValue_desc(void);
asn_struct_free_f OtherHashValue_free;
asn_struct_print_f OtherHashValue_print;
asn_constr_check_f OtherHashValue_constraint;
ber_type_decoder_f OtherHashValue_decode_ber;
der_type_encoder_f OtherHashValue_encode_der;
xer_type_decoder_f OtherHashValue_decode_xer;
xer_type_encoder_f OtherHashValue_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
