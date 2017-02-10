/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _MessageAuthenticationCodeAlgorithm_H_
#define    _MessageAuthenticationCodeAlgorithm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* MessageAuthenticationCodeAlgorithm */
typedef AlgorithmIdentifier_t     MessageAuthenticationCodeAlgorithm_t;

/* Implementation */
extern asn_TYPE_descriptor_t MessageAuthenticationCodeAlgorithm_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_MessageAuthenticationCodeAlgorithm_desc(void);
asn_struct_free_f MessageAuthenticationCodeAlgorithm_free;
asn_struct_print_f MessageAuthenticationCodeAlgorithm_print;
asn_constr_check_f MessageAuthenticationCodeAlgorithm_constraint;
ber_type_decoder_f MessageAuthenticationCodeAlgorithm_decode_ber;
der_type_encoder_f MessageAuthenticationCodeAlgorithm_encode_der;
xer_type_decoder_f MessageAuthenticationCodeAlgorithm_decode_xer;
xer_type_encoder_f MessageAuthenticationCodeAlgorithm_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
