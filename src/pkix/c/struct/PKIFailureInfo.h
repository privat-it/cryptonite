/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PKIFailureInfo_H_
#define    _PKIFailureInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BIT_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PKIFailureInfo {
    PKIFailureInfo_badAlg    = 0,
    PKIFailureInfo_badRequest    = 2,
    PKIFailureInfo_badDataFormat    = 5,
    PKIFailureInfo_timeNotAvailable    = 14,
    PKIFailureInfo_unacceptedPolicy    = 15,
    PKIFailureInfo_unacceptedExtension    = 16,
    PKIFailureInfo_addInfoNotAvailable    = 17,
    PKIFailureInfo_systemFailure    = 25
} e_PKIFailureInfo;

/* PKIFailureInfo */
typedef BIT_STRING_t     PKIFailureInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t PKIFailureInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PKIFailureInfo_desc(void);
asn_struct_free_f PKIFailureInfo_free;
asn_struct_print_f PKIFailureInfo_print;
asn_constr_check_f PKIFailureInfo_constraint;
ber_type_decoder_f PKIFailureInfo_decode_ber;
der_type_encoder_f PKIFailureInfo_encode_der;
xer_type_decoder_f PKIFailureInfo_decode_xer;
xer_type_encoder_f PKIFailureInfo_encode_xer;

#ifdef __cplusplus
}
#endif

#endif
