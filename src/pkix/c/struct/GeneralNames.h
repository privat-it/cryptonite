/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _GeneralNames_H_
#define    _GeneralNames_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GeneralName;

/* GeneralNames */
typedef struct GeneralNames {
    A_SEQUENCE_OF(struct GeneralName) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} GeneralNames_t;

/* Implementation */
extern asn_TYPE_descriptor_t GeneralNames_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_GeneralNames_desc(void);

#ifdef __cplusplus
}
#endif

#endif
