/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKIStatus_H_
#define    _PKIStatus_H_


#include "asn_application.h"

/* Including external dependencies */
#include "INTEGER.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PKIStatus {
    PKIStatus_granted    = 0,
    PKIStatus_grantedWithMods    = 1,
    PKIStatus_rejection    = 2,
    PKIStatus_waiting    = 3,
    PKIStatus_revocationWarning    = 4,
    PKIStatus_revocationNotification    = 5
} e_PKIStatus;

/* PKIStatus */
typedef INTEGER_t     PKIStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIStatus_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKIStatus_desc(void);
asn_struct_free_f PKIStatus_free;
asn_struct_print_f PKIStatus_print;
asn_constr_check_f PKIStatus_constraint;
ber_type_decoder_f PKIStatus_decode_ber;
der_type_encoder_f PKIStatus_encode_der;
xer_type_decoder_f PKIStatus_decode_xer;
xer_type_encoder_f PKIStatus_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
