/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificateSerialNumber_H_
#define    _CertificateSerialNumber_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificateSerialNumber */
typedef INTEGER_t     CertificateSerialNumber_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificateSerialNumber_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificateSerialNumber_desc(void);
asn_struct_free_f CertificateSerialNumber_free;
asn_struct_print_f CertificateSerialNumber_print;
asn_constr_check_f CertificateSerialNumber_constraint;
ber_type_decoder_f CertificateSerialNumber_decode_ber;
der_type_encoder_f CertificateSerialNumber_encode_der;
xer_type_decoder_f CertificateSerialNumber_decode_xer;
xer_type_encoder_f CertificateSerialNumber_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
