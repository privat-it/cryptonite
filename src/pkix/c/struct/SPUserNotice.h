/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SPUserNotice_H_
#define    _SPUserNotice_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NoticeReference;
struct DisplayText;

/* SPUserNotice */
typedef struct SPUserNotice {
    struct NoticeReference    *noticeRef    /* OPTIONAL */;
    struct DisplayText    *explicitText    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SPUserNotice_t;

/* Implementation */
extern asn_TYPE_descriptor_t SPUserNotice_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SPUserNotice_desc(void);

#ifdef __cplusplus
}
#endif

#endif
