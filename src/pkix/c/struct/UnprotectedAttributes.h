/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UnprotectedAttributes_H_
#define    _UnprotectedAttributes_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UnprotectedAttributes */
typedef Attributes_t     UnprotectedAttributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t UnprotectedAttributes_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UnprotectedAttributes_desc(void);
asn_struct_free_f UnprotectedAttributes_free;
asn_struct_print_f UnprotectedAttributes_print;
asn_constr_check_f UnprotectedAttributes_constraint;
ber_type_decoder_f UnprotectedAttributes_decode_ber;
der_type_encoder_f UnprotectedAttributes_encode_der;
xer_type_decoder_f UnprotectedAttributes_decode_xer;
xer_type_encoder_f UnprotectedAttributes_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
