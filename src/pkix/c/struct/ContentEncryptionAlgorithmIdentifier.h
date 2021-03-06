/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ContentEncryptionAlgorithmIdentifier_H_
#define    _ContentEncryptionAlgorithmIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ContentEncryptionAlgorithmIdentifier */
typedef AlgorithmIdentifier_t     ContentEncryptionAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t ContentEncryptionAlgorithmIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ContentEncryptionAlgorithmIdentifier_desc(void);
asn_struct_free_f ContentEncryptionAlgorithmIdentifier_free;
asn_struct_print_f ContentEncryptionAlgorithmIdentifier_print;
asn_constr_check_f ContentEncryptionAlgorithmIdentifier_constraint;
ber_type_decoder_f ContentEncryptionAlgorithmIdentifier_decode_ber;
der_type_encoder_f ContentEncryptionAlgorithmIdentifier_encode_der;
xer_type_decoder_f ContentEncryptionAlgorithmIdentifier_decode_xer;
xer_type_encoder_f ContentEncryptionAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
