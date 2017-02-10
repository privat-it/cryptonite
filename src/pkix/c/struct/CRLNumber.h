/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CRLNumber_H_
#define    _CRLNumber_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CRLNumber */
typedef INTEGER_t     CRLNumber_t;

/* Implementation */
extern asn_TYPE_descriptor_t CRLNumber_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CRLNumber_desc(void);
asn_struct_free_f CRLNumber_free;
asn_struct_print_f CRLNumber_print;
asn_constr_check_f CRLNumber_constraint;
ber_type_decoder_f CRLNumber_decode_ber;
der_type_encoder_f CRLNumber_encode_der;
xer_type_decoder_f CRLNumber_decode_xer;
xer_type_encoder_f CRLNumber_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
