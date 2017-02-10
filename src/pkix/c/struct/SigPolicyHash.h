/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SigPolicyHash_H_
#define    _SigPolicyHash_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OtherHashAlgAndValue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SigPolicyHash */
typedef OtherHashAlgAndValue_t     SigPolicyHash_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigPolicyHash_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SigPolicyHash_desc(void);
asn_struct_free_f SigPolicyHash_free;
asn_struct_print_f SigPolicyHash_print;
asn_constr_check_f SigPolicyHash_constraint;
ber_type_decoder_f SigPolicyHash_decode_ber;
der_type_encoder_f SigPolicyHash_encode_der;
xer_type_decoder_f SigPolicyHash_decode_xer;
xer_type_encoder_f SigPolicyHash_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
