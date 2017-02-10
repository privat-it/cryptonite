/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OrganizationName_H_
#define    _OrganizationName_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PrintableString.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OrganizationName */
typedef PrintableString_t     OrganizationName_t;

/* Implementation */
extern asn_TYPE_descriptor_t OrganizationName_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OrganizationName_desc(void);
asn_struct_free_f OrganizationName_free;
asn_struct_print_f OrganizationName_print;
asn_constr_check_f OrganizationName_constraint;
ber_type_decoder_f OrganizationName_decode_ber;
der_type_encoder_f OrganizationName_encode_der;
xer_type_decoder_f OrganizationName_decode_xer;
xer_type_encoder_f OrganizationName_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
