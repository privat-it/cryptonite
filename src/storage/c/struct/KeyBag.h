/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyBag_H_
#define    _KeyBag_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrivateKeyInfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyBag */
typedef PrivateKeyInfo_t     KeyBag_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyBag_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyBag_desc(void);
asn_struct_free_f KeyBag_free;
asn_struct_print_f KeyBag_print;
asn_constr_check_f KeyBag_constraint;
ber_type_decoder_f KeyBag_decode_ber;
der_type_encoder_f KeyBag_encode_der;
xer_type_decoder_f KeyBag_decode_xer;
xer_type_encoder_f KeyBag_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
