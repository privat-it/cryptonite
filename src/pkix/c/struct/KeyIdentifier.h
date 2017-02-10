/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyIdentifier_H_
#define    _KeyIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyIdentifier */
typedef OCTET_STRING_t     KeyIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyIdentifier_desc(void);
asn_struct_free_f KeyIdentifier_free;
asn_struct_print_f KeyIdentifier_print;
asn_constr_check_f KeyIdentifier_constraint;
ber_type_decoder_f KeyIdentifier_decode_ber;
der_type_encoder_f KeyIdentifier_encode_der;
xer_type_decoder_f KeyIdentifier_decode_xer;
xer_type_encoder_f KeyIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
