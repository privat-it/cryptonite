/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyPurposeId_H_
#define    _KeyPurposeId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyPurposeId */
typedef OBJECT_IDENTIFIER_t     KeyPurposeId_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyPurposeId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyPurposeId_desc(void);
asn_struct_free_f KeyPurposeId_free;
asn_struct_print_f KeyPurposeId_print;
asn_constr_check_f KeyPurposeId_constraint;
ber_type_decoder_f KeyPurposeId_decode_ber;
der_type_encoder_f KeyPurposeId_encode_der;
xer_type_decoder_f KeyPurposeId_decode_xer;
xer_type_encoder_f KeyPurposeId_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
