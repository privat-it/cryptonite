/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _NoticeReference_H_
#define    _NoticeReference_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DisplayText.h"
#include "INTEGER.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NoticeReference */
typedef struct NoticeReference {
    DisplayText_t     organization;
    struct noticeNumbers {
        A_SEQUENCE_OF(INTEGER_t) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } noticeNumbers;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} NoticeReference_t;

/* Implementation */
extern asn_TYPE_descriptor_t NoticeReference_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_NoticeReference_desc(void);

#ifdef __cplusplus
}
#endif

#endif
