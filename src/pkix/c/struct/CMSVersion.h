/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CMSVersion_H_
#define    _CMSVersion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CMSVersion {
    CMSVersion_v0    = 0,
    CMSVersion_v1    = 1,
    CMSVersion_v2    = 2,
    CMSVersion_v3    = 3,
    CMSVersion_v4    = 4,
    CMSVersion_v5    = 5
} e_CMSVersion;

/* CMSVersion */
typedef INTEGER_t     CMSVersion_t;

/* Implementation */
extern asn_TYPE_descriptor_t CMSVersion_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CMSVersion_desc(void);
asn_struct_free_f CMSVersion_free;
asn_struct_print_f CMSVersion_print;
asn_constr_check_f CMSVersion_constraint;
ber_type_decoder_f CMSVersion_decode_ber;
der_type_encoder_f CMSVersion_encode_der;
xer_type_decoder_f CMSVersion_decode_xer;
xer_type_encoder_f CMSVersion_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
