/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UnknownInfo_H_
#define    _UnknownInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NULL.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UnknownInfo */
typedef NULL_t     UnknownInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t UnknownInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UnknownInfo_desc(void);
asn_struct_free_f UnknownInfo_free;
asn_struct_print_f UnknownInfo_print;
asn_constr_check_f UnknownInfo_constraint;
ber_type_decoder_f UnknownInfo_decode_ber;
der_type_encoder_f UnknownInfo_encode_der;
xer_type_decoder_f UnknownInfo_decode_xer;
xer_type_encoder_f UnknownInfo_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
