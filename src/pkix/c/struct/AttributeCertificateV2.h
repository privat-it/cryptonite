/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AttributeCertificateV2_H_
#define    _AttributeCertificateV2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AttributeCertificate.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AttributeCertificateV2 */
typedef AttributeCertificate_t     AttributeCertificateV2_t;

/* Implementation */
extern asn_TYPE_descriptor_t AttributeCertificateV2_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AttributeCertificateV2_desc(void);
asn_struct_free_f AttributeCertificateV2_free;
asn_struct_print_f AttributeCertificateV2_print;
asn_constr_check_f AttributeCertificateV2_constraint;
ber_type_decoder_f AttributeCertificateV2_decode_ber;
der_type_encoder_f AttributeCertificateV2_encode_der;
xer_type_decoder_f AttributeCertificateV2_decode_xer;
xer_type_encoder_f AttributeCertificateV2_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
