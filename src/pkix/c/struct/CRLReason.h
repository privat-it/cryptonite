/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CRLReason_H_
#define    _CRLReason_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ENUMERATED.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CRLReason {
    CRLReason_unspecified    = 0,
    CRLReason_keyCompromise    = 1,
    CRLReason_cACompromise    = 2,
    CRLReason_affiliationChanged    = 3,
    CRLReason_superseded    = 4,
    CRLReason_cessationOfOperation    = 5,
    CRLReason_certificateHold    = 6,
    CRLReason_removeFromCRL    = 8,
    CRLReason_privilegeWithdrawn    = 9,
    CRLReason_aACompromise    = 10
} e_CRLReason;

/* CRLReason */
typedef ENUMERATED_t     CRLReason_t;

/* Implementation */
extern asn_TYPE_descriptor_t CRLReason_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CRLReason_desc(void);
asn_struct_free_f CRLReason_free;
asn_struct_print_f CRLReason_print;
asn_constr_check_f CRLReason_constraint;
ber_type_decoder_f CRLReason_decode_ber;
der_type_encoder_f CRLReason_encode_der;
xer_type_decoder_f CRLReason_decode_xer;
xer_type_encoder_f CRLReason_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
