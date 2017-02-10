/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SigPolicyQualifierId_H_
#define    _SigPolicyQualifierId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SigPolicyQualifierId */
typedef OBJECT_IDENTIFIER_t     SigPolicyQualifierId_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigPolicyQualifierId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SigPolicyQualifierId_desc(void);
asn_struct_free_f SigPolicyQualifierId_free;
asn_struct_print_f SigPolicyQualifierId_print;
asn_constr_check_f SigPolicyQualifierId_constraint;
ber_type_decoder_f SigPolicyQualifierId_decode_ber;
der_type_encoder_f SigPolicyQualifierId_encode_der;
xer_type_decoder_f SigPolicyQualifierId_decode_xer;
xer_type_encoder_f SigPolicyQualifierId_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
