/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificateSet_H_
#define    _CertificateSet_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SET_OF.h"
#include "constr_SET_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct CertificateChoices;

/* CertificateSet */
typedef struct CertificateSet {
    A_SET_OF(struct CertificateChoices) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertificateSet_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificateSet_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificateSet_desc(void);

#ifdef __cplusplus
}
#endif

#endif
