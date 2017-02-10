/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SigPolicyId_H_
#define    _SigPolicyId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SigPolicyId */
typedef OBJECT_IDENTIFIER_t     SigPolicyId_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigPolicyId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SigPolicyId_desc(void);
asn_struct_free_f SigPolicyId_free;
asn_struct_print_f SigPolicyId_print;
asn_constr_check_f SigPolicyId_constraint;
ber_type_decoder_f SigPolicyId_decode_ber;
der_type_encoder_f SigPolicyId_encode_der;
xer_type_decoder_f SigPolicyId_decode_xer;
xer_type_encoder_f SigPolicyId_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
