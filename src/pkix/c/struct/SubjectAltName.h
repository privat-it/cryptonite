/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SubjectAltName_H_
#define    _SubjectAltName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "GeneralNames.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SubjectAltName */
typedef GeneralNames_t     SubjectAltName_t;

/* Implementation */
extern asn_TYPE_descriptor_t SubjectAltName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SubjectAltName_desc(void);
asn_struct_free_f SubjectAltName_free;
asn_struct_print_f SubjectAltName_print;
asn_constr_check_f SubjectAltName_constraint;
ber_type_decoder_f SubjectAltName_decode_ber;
der_type_encoder_f SubjectAltName_encode_der;
xer_type_decoder_f SubjectAltName_decode_xer;
xer_type_encoder_f SubjectAltName_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
