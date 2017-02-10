/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyEncryptionAlgorithmIdentifier_H_
#define    _KeyEncryptionAlgorithmIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyEncryptionAlgorithmIdentifier */
typedef AlgorithmIdentifier_t     KeyEncryptionAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyEncryptionAlgorithmIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyEncryptionAlgorithmIdentifier_desc(void);
asn_struct_free_f KeyEncryptionAlgorithmIdentifier_free;
asn_struct_print_f KeyEncryptionAlgorithmIdentifier_print;
asn_constr_check_f KeyEncryptionAlgorithmIdentifier_constraint;
ber_type_decoder_f KeyEncryptionAlgorithmIdentifier_decode_ber;
der_type_encoder_f KeyEncryptionAlgorithmIdentifier_encode_der;
xer_type_decoder_f KeyEncryptionAlgorithmIdentifier_decode_xer;
xer_type_encoder_f KeyEncryptionAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
