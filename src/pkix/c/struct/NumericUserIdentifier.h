/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NumericUserIdentifier_H_
#define    _NumericUserIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NumericString.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NumericUserIdentifier */
typedef NumericString_t     NumericUserIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t NumericUserIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NumericUserIdentifier_desc(void);
asn_struct_free_f NumericUserIdentifier_free;
asn_struct_print_f NumericUserIdentifier_print;
asn_constr_check_f NumericUserIdentifier_constraint;
ber_type_decoder_f NumericUserIdentifier_decode_ber;
der_type_encoder_f NumericUserIdentifier_encode_der;
xer_type_decoder_f NumericUserIdentifier_decode_xer;
xer_type_encoder_f NumericUserIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
