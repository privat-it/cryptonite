/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RELATIVE_OID_H_
#define    _RELATIVE_OID_H_

#include "OBJECT_IDENTIFIER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Implemented via OBJECT IDENTIFIER */
typedef OBJECT_IDENTIFIER_t RELATIVE_OID_t;

extern asn_TYPE_descriptor_t RELATIVE_OID_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RELATIVE_OID_desc(void);

asn_struct_print_f RELATIVE_OID_print;
xer_type_decoder_f RELATIVE_OID_decode_xer;
xer_type_encoder_f RELATIVE_OID_encode_xer;

/**********************************
 * Some handy conversion routines *
 **********************************/

/* See OBJECT_IDENTIFIER_get_arcs() function in OBJECT_IDENTIFIER.h */
CRYPTONITE_EXPORT int RELATIVE_OID_get_arcs(const RELATIVE_OID_t *_roid,
        void *arcs, unsigned int arc_type_size, unsigned int arc_slots);

/* See OBJECT_IDENTIFIER_set_arcs() function in OBJECT_IDENTIFIER.h */
CRYPTONITE_EXPORT int RELATIVE_OID_set_arcs(RELATIVE_OID_t *_roid,
        void *arcs, unsigned int arc_type_size, unsigned int arcs_slots);

#ifdef __cplusplus
}
#endif

#endif
