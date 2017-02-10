/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SubjectKeyIdentifier_H_
#define    _SubjectKeyIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SubjectKeyIdentifier */
typedef OCTET_STRING_t     SubjectKeyIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t SubjectKeyIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SubjectKeyIdentifier_desc(void);
asn_struct_free_f SubjectKeyIdentifier_free;
asn_struct_print_f SubjectKeyIdentifier_print;
asn_constr_check_f SubjectKeyIdentifier_constraint;
ber_type_decoder_f SubjectKeyIdentifier_decode_ber;
der_type_encoder_f SubjectKeyIdentifier_encode_der;
xer_type_decoder_f SubjectKeyIdentifier_decode_xer;
xer_type_encoder_f SubjectKeyIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
