/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OCSPResponseStatus_H_
#define    _OCSPResponseStatus_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ENUMERATED.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OCSPResponseStatus {
    OCSPResponseStatus_successful    = 0,
    OCSPResponseStatus_malformedRequest    = 1,
    OCSPResponseStatus_internalError    = 2,
    OCSPResponseStatus_tryLater    = 3,
    OCSPResponseStatus_sigRequired    = 5,
    OCSPResponseStatus_unauthorized    = 6
} e_OCSPResponseStatus;

/* OCSPResponseStatus */
typedef ENUMERATED_t     OCSPResponseStatus_t;

/* Implementation */
extern asn_TYPE_descriptor_t OCSPResponseStatus_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OCSPResponseStatus_desc(void);
asn_struct_free_f OCSPResponseStatus_free;
asn_struct_print_f OCSPResponseStatus_print;
asn_constr_check_f OCSPResponseStatus_constraint;
ber_type_decoder_f OCSPResponseStatus_decode_ber;
der_type_encoder_f OCSPResponseStatus_encode_der;
xer_type_decoder_f OCSPResponseStatus_decode_xer;
xer_type_encoder_f OCSPResponseStatus_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
