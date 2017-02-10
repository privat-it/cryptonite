/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _Digest_H_
#define    _Digest_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Digest */
typedef OCTET_STRING_t     Digest_t;

/* Implementation */
extern asn_TYPE_descriptor_t Digest_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_Digest_desc(void);
asn_struct_free_f Digest_free;
asn_struct_print_f Digest_print;
asn_constr_check_f Digest_constraint;
ber_type_decoder_f Digest_decode_ber;
der_type_encoder_f Digest_encode_der;
xer_type_decoder_f Digest_decode_xer;
xer_type_encoder_f Digest_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
