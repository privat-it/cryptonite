/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PolicyQualifierId_H_
#define    _PolicyQualifierId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PolicyQualifierId */
typedef OBJECT_IDENTIFIER_t     PolicyQualifierId_t;

/* Implementation */
extern asn_TYPE_descriptor_t PolicyQualifierId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PolicyQualifierId_desc(void);
asn_struct_free_f PolicyQualifierId_free;
asn_struct_print_f PolicyQualifierId_print;
asn_constr_check_f PolicyQualifierId_constraint;
ber_type_decoder_f PolicyQualifierId_decode_ber;
der_type_encoder_f PolicyQualifierId_encode_der;
xer_type_decoder_f PolicyQualifierId_decode_xer;
xer_type_encoder_f PolicyQualifierId_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
