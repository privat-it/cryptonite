/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _ReasonFlags_H_
#define    _ReasonFlags_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BIT_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ReasonFlags {
    ReasonFlags_unused    = 0,
    ReasonFlags_keyCompromise    = 1,
    ReasonFlags_cACompromise    = 2,
    ReasonFlags_affiliationChanged    = 3,
    ReasonFlags_superseded    = 4,
    ReasonFlags_cessationOfOperation    = 5,
    ReasonFlags_certificateHold    = 6,
    ReasonFlags_privilegeWithdrawn    = 7
} e_ReasonFlags;

/* ReasonFlags */
typedef BIT_STRING_t     ReasonFlags_t;

/* Implementation */
extern asn_TYPE_descriptor_t ReasonFlags_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_ReasonFlags_desc(void);
asn_struct_free_f ReasonFlags_free;
asn_struct_print_f ReasonFlags_print;
asn_constr_check_f ReasonFlags_constraint;
ber_type_decoder_f ReasonFlags_decode_ber;
der_type_encoder_f ReasonFlags_encode_der;
xer_type_decoder_f ReasonFlags_decode_xer;
xer_type_encoder_f ReasonFlags_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
