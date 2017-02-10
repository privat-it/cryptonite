/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _IssuerAltName_H_
#define    _IssuerAltName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralNames.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IssuerAltName */
typedef GeneralNames_t     IssuerAltName_t;

/* Implementation */
extern asn_TYPE_descriptor_t IssuerAltName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_IssuerAltName_desc(void);
asn_struct_free_f IssuerAltName_free;
asn_struct_print_f IssuerAltName_print;
asn_constr_check_f IssuerAltName_constraint;
ber_type_decoder_f IssuerAltName_decode_ber;
der_type_encoder_f IssuerAltName_encode_der;
xer_type_decoder_f IssuerAltName_decode_xer;
xer_type_encoder_f IssuerAltName_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
