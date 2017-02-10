/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyUsage_H_
#define    _KeyUsage_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BIT_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum KeyUsage {
    KeyUsage_digitalSignature    = 0,
    KeyUsage_nonRepudiation    = 1,
    KeyUsage_keyEncipherment    = 2,
    KeyUsage_dataEncipherment    = 3,
    KeyUsage_keyAgreement    = 4,
    KeyUsage_keyCertSign    = 5,
    KeyUsage_crlSign    = 6,
    KeyUsage_encipherOnly    = 7,
    KeyUsage_decipherOnly    = 8
} e_KeyUsage;

/* KeyUsage */
typedef BIT_STRING_t     KeyUsage_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyUsage_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyUsage_desc(void);
asn_struct_free_f KeyUsage_free;
asn_struct_print_f KeyUsage_print;
asn_constr_check_f KeyUsage_constraint;
ber_type_decoder_f KeyUsage_decode_ber;
der_type_encoder_f KeyUsage_encode_der;
xer_type_decoder_f KeyUsage_decode_xer;
xer_type_encoder_f KeyUsage_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
