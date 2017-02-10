/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _QcEuLimitValue_H_
#define    _QcEuLimitValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "MonetaryValue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* QcEuLimitValue */
typedef MonetaryValue_t     QcEuLimitValue_t;

/* Implementation */
extern asn_TYPE_descriptor_t QcEuLimitValue_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_QcEuLimitValue_desc(void);
asn_struct_free_f QcEuLimitValue_free;
asn_struct_print_f QcEuLimitValue_print;
asn_constr_check_f QcEuLimitValue_constraint;
ber_type_decoder_f QcEuLimitValue_decode_ber;
der_type_encoder_f QcEuLimitValue_encode_der;
xer_type_decoder_f QcEuLimitValue_decode_xer;
xer_type_encoder_f QcEuLimitValue_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
