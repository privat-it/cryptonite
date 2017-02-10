/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignerIdentifier_H_
#define    _SignerIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ANY.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SignerIdentifier */
typedef ANY_t     SignerIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignerIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignerIdentifier_desc(void);
asn_struct_free_f SignerIdentifier_free;
asn_struct_print_f SignerIdentifier_print;
asn_constr_check_f SignerIdentifier_constraint;
ber_type_decoder_f SignerIdentifier_decode_ber;
der_type_encoder_f SignerIdentifier_encode_der;
xer_type_decoder_f SignerIdentifier_decode_xer;
xer_type_encoder_f SignerIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
