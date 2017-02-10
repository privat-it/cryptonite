/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _DigestAlgorithmIdentifier_H_
#define    _DigestAlgorithmIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DigestAlgorithmIdentifier */
typedef AlgorithmIdentifier_t     DigestAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t DigestAlgorithmIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_DigestAlgorithmIdentifier_desc(void);
asn_struct_free_f DigestAlgorithmIdentifier_free;
asn_struct_print_f DigestAlgorithmIdentifier_print;
asn_constr_check_f DigestAlgorithmIdentifier_constraint;
ber_type_decoder_f DigestAlgorithmIdentifier_decode_ber;
der_type_encoder_f DigestAlgorithmIdentifier_encode_der;
xer_type_decoder_f DigestAlgorithmIdentifier_decode_xer;
xer_type_encoder_f DigestAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
