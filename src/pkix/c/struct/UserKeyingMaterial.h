/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UserKeyingMaterial_H_
#define    _UserKeyingMaterial_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UserKeyingMaterial */
typedef OCTET_STRING_t     UserKeyingMaterial_t;

/* Implementation */
extern asn_TYPE_descriptor_t UserKeyingMaterial_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UserKeyingMaterial_desc(void);
asn_struct_free_f UserKeyingMaterial_free;
asn_struct_print_f UserKeyingMaterial_print;
asn_constr_check_f UserKeyingMaterial_constraint;
ber_type_decoder_f UserKeyingMaterial_decode_ber;
der_type_encoder_f UserKeyingMaterial_encode_der;
xer_type_decoder_f UserKeyingMaterial_decode_xer;
xer_type_encoder_f UserKeyingMaterial_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
