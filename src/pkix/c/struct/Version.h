/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Version_H_
#define    _Version_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Version {
    Version_v1    = 0,
    Version_v2    = 1,
    Version_v3    = 2
} e_Version;

/* Version */
typedef INTEGER_t     Version_t;

/* Implementation */
extern asn_TYPE_descriptor_t Version_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Version_desc(void);
asn_struct_free_f Version_free;
asn_struct_print_f Version_print;
asn_constr_check_f Version_constraint;
ber_type_decoder_f Version_decode_ber;
der_type_encoder_f Version_encode_der;
xer_type_decoder_f Version_decode_xer;
xer_type_encoder_f Version_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
