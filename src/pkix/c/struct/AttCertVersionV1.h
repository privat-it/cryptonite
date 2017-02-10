/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttCertVersionV1_H_
#define    _AttCertVersionV1_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AttCertVersionV1 {
    AttCertVersionV1_v1    = 0
} e_AttCertVersionV1;

/* AttCertVersionV1 */
typedef INTEGER_t     AttCertVersionV1_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttCertVersionV1_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttCertVersionV1_desc(void);
asn_struct_free_f AttCertVersionV1_free;
asn_struct_print_f AttCertVersionV1_print;
asn_constr_check_f AttCertVersionV1_constraint;
ber_type_decoder_f AttCertVersionV1_decode_ber;
der_type_encoder_f AttCertVersionV1_encode_der;
xer_type_decoder_f AttCertVersionV1_decode_xer;
xer_type_encoder_f AttCertVersionV1_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
