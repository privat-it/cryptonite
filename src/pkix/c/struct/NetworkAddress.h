/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NetworkAddress_H_
#define    _NetworkAddress_H_


#include "asn_application.h"

/* Including external dependencies */
#include "X121Address.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NetworkAddress */
typedef X121Address_t     NetworkAddress_t;

/* Implementation */
extern asn_TYPE_descriptor_t NetworkAddress_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NetworkAddress_desc(void);
asn_struct_free_f NetworkAddress_free;
asn_struct_print_f NetworkAddress_print;
asn_constr_check_f NetworkAddress_constraint;
ber_type_decoder_f NetworkAddress_decode_ber;
der_type_encoder_f NetworkAddress_encode_der;
xer_type_decoder_f NetworkAddress_decode_xer;
xer_type_encoder_f NetworkAddress_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
