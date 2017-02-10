/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKCS8ShroudedKeyBag_H_
#define    _PKCS8ShroudedKeyBag_H_


#include "asn_application.h"

/* Including external dependencies */
#include "EncryptedPrivateKeyInfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PKCS8ShroudedKeyBag */
typedef EncryptedPrivateKeyInfo_t     PKCS8ShroudedKeyBag_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKCS8ShroudedKeyBag_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKCS8ShroudedKeyBag_desc(void);
asn_struct_free_f PKCS8ShroudedKeyBag_free;
asn_struct_print_f PKCS8ShroudedKeyBag_print;
asn_constr_check_f PKCS8ShroudedKeyBag_constraint;
ber_type_decoder_f PKCS8ShroudedKeyBag_decode_ber;
der_type_encoder_f PKCS8ShroudedKeyBag_encode_der;
xer_type_decoder_f PKCS8ShroudedKeyBag_decode_xer;
xer_type_encoder_f PKCS8ShroudedKeyBag_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
