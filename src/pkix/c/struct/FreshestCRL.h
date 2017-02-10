/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _FreshestCRL_H_
#define    _FreshestCRL_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CRLDistributionPoints.h"

#ifdef __cplusplus
extern "C" {
#endif

/* FreshestCRL */
typedef CRLDistributionPoints_t     FreshestCRL_t;

/* Implementation */
extern asn_TYPE_descriptor_t FreshestCRL_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_FreshestCRL_desc(void);
asn_struct_free_f FreshestCRL_free;
asn_struct_print_f FreshestCRL_print;
asn_constr_check_f FreshestCRL_constraint;
ber_type_decoder_f FreshestCRL_decode_ber;
der_type_encoder_f FreshestCRL_encode_der;
xer_type_decoder_f FreshestCRL_decode_xer;
xer_type_encoder_f FreshestCRL_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
