/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _OtherRecipientInfo_H_
#define    _OtherRecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OBJECT_IDENTIFIER.h"
#include "ANY.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* OtherRecipientInfo */
typedef struct OtherRecipientInfo {
    OBJECT_IDENTIFIER_t     oriType;
    ANY_t     oriValue;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} OtherRecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t OtherRecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_OtherRecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
