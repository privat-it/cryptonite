/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EncryptedKey_H_
#define    _EncryptedKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EncryptedKey */
typedef OCTET_STRING_t     EncryptedKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t EncryptedKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EncryptedKey_desc(void);
asn_struct_free_f EncryptedKey_free;
asn_struct_print_f EncryptedKey_print;
asn_constr_check_f EncryptedKey_constraint;
ber_type_decoder_f EncryptedKey_decode_ber;
der_type_encoder_f EncryptedKey_encode_der;
xer_type_decoder_f EncryptedKey_decode_xer;
xer_type_encoder_f EncryptedKey_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
