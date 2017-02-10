/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _UTCTime_H_
#define    _UTCTime_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t UTCTime_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t UTCTime_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_UTCTime_desc(void);

asn_struct_print_f UTCTime_print;
asn_constr_check_f UTCTime_constraint;
xer_type_encoder_f UTCTime_encode_xer;

/***********************
 * Some handy helpers. *
 ***********************/

struct tm;    /* <time.h> */

/* See asn_GT2time() in GeneralizedTime.h */
CRYPTONITE_EXPORT time_t  asn_UT2time(const UTCTime_t *, struct tm *_optional_tm4fill, int as_gmt);

/* See asn_time2GT() in GeneralizedTime.h */
CRYPTONITE_EXPORT UTCTime_t *asn_time2UT(UTCTime_t *__opt_ut, const struct tm *, int force_gmt);

#ifdef __cplusplus
}
#endif

#endif
