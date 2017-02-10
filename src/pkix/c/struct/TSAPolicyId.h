/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TSAPolicyId_H_
#define    _TSAPolicyId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TSAPolicyId */
typedef OBJECT_IDENTIFIER_t     TSAPolicyId_t;

/* Implementation */
extern asn_TYPE_descriptor_t TSAPolicyId_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TSAPolicyId_desc(void);
asn_struct_free_f TSAPolicyId_free;
asn_struct_print_f TSAPolicyId_print;
asn_constr_check_f TSAPolicyId_constraint;
ber_type_decoder_f TSAPolicyId_decode_ber;
der_type_encoder_f TSAPolicyId_encode_der;
xer_type_decoder_f TSAPolicyId_decode_xer;
xer_type_encoder_f TSAPolicyId_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
