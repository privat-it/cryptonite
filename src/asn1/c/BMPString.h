/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _BMPString_H_
#define    _BMPString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t BMPString_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t BMPString_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_BMPString_desc(void);

asn_struct_print_f BMPString_print;    /* Human-readable output */
xer_type_decoder_f BMPString_decode_xer;
xer_type_encoder_f BMPString_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
