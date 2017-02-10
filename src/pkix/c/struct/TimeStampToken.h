/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TimeStampToken_H_
#define    _TimeStampToken_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ContentInfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TimeStampToken */
typedef ContentInfo_t     TimeStampToken_t;

/* Implementation */
extern asn_TYPE_descriptor_t TimeStampToken_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TimeStampToken_desc(void);
asn_struct_free_f TimeStampToken_free;
asn_struct_print_f TimeStampToken_print;
asn_constr_check_f TimeStampToken_constraint;
ber_type_decoder_f TimeStampToken_decode_ber;
der_type_encoder_f TimeStampToken_encode_der;
xer_type_decoder_f TimeStampToken_decode_xer;
xer_type_encoder_f TimeStampToken_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
