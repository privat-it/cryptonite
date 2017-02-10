/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttCertVersion_H_
#define    _AttCertVersion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AttCertVersion {
    AttCertVersion_v2    = 1
} e_AttCertVersion;

/* AttCertVersion */
typedef INTEGER_t     AttCertVersion_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttCertVersion_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttCertVersion_desc(void);
asn_struct_free_f AttCertVersion_free;
asn_struct_print_f AttCertVersion_print;
asn_constr_check_f AttCertVersion_constraint;
ber_type_decoder_f AttCertVersion_decode_ber;
der_type_encoder_f AttCertVersion_encode_der;
xer_type_decoder_f AttCertVersion_decode_xer;
xer_type_encoder_f AttCertVersion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
