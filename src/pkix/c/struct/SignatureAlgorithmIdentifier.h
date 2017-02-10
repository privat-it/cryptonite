/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SignatureAlgorithmIdentifier_H_
#define    _SignatureAlgorithmIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SignatureAlgorithmIdentifier */
typedef AlgorithmIdentifier_t     SignatureAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t SignatureAlgorithmIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SignatureAlgorithmIdentifier_desc(void);
asn_struct_free_f SignatureAlgorithmIdentifier_free;
asn_struct_print_f SignatureAlgorithmIdentifier_print;
asn_constr_check_f SignatureAlgorithmIdentifier_constraint;
ber_type_decoder_f SignatureAlgorithmIdentifier_decode_ber;
der_type_encoder_f SignatureAlgorithmIdentifier_encode_der;
xer_type_decoder_f SignatureAlgorithmIdentifier_decode_xer;
xer_type_encoder_f SignatureAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
