/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TSVersion_H_
#define    _TSVersion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TSVersion {
    TSVersion_v1    = 1
} e_TSVersion;

/* TSVersion */
typedef INTEGER_t     TSVersion_t;

/* Implementation */
extern asn_TYPE_descriptor_t TSVersion_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TSVersion_desc(void);
asn_struct_free_f TSVersion_free;
asn_struct_print_f TSVersion_print;
asn_constr_check_f TSVersion_constraint;
ber_type_decoder_f TSVersion_decode_ber;
der_type_encoder_f TSVersion_encode_der;
xer_type_decoder_f TSVersion_decode_xer;
xer_type_encoder_f TSVersion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
