/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ENUMERATED_H_
#define    _ENUMERATED_H_

#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef INTEGER_t ENUMERATED_t;        /* Implemented via INTEGER */

extern asn_TYPE_descriptor_t ENUMERATED_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ENUMERATED_desc(void);

per_type_decoder_f ENUMERATED_decode_uper;
per_type_encoder_f ENUMERATED_encode_uper;

#ifdef __cplusplus
}
#endif

#endif
