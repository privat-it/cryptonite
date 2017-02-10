/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef ASN_TYPE_ANY_H
#define ASN_TYPE_ANY_H

#include "OCTET_STRING.h"    /* Implemented via OCTET STRING type */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ANY {
    uint8_t *buf;    /* BER-encoded ANY contents */
    int size;        /* Size of the above buffer */

    asn_struct_ctx_t _asn_ctx;    /* Parsing across buffer boundaries */
} ANY_t;

extern asn_TYPE_descriptor_t ANY_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ANY_desc(void);

asn_struct_free_f ANY_free;
asn_struct_print_f ANY_print;
ber_type_decoder_f ANY_decode_ber;
der_type_encoder_f ANY_encode_der;
xer_type_encoder_f ANY_encode_xer;

/******************************
 * Handy conversion routines. *
 ******************************/

/* Convert another ASN.1 type into the ANY. This implies DER encoding. */
CRYPTONITE_EXPORT int ANY_fromType(ANY_t *, asn_TYPE_descriptor_t *td, void *struct_ptr);
CRYPTONITE_EXPORT ANY_t *ANY_new_fromType(asn_TYPE_descriptor_t *td, void *struct_ptr);

/* Convert the contents of the ANY type into the specified type. */
int ANY_to_type(const ANY_t *, asn_TYPE_descriptor_t *td, void **struct_ptr);

#define    ANY_fromBuf(s, buf, size)    OCTET_STRING_fromBuf((s), (buf), (size))
#define    ANY_new_fromBuf(buf, size)    OCTET_STRING_new_fromBuf(    \
                        &ANY_desc, (buf), (size))

#ifdef __cplusplus
}
#endif

#endif
