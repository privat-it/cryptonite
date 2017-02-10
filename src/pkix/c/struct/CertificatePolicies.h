/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificatePolicies_H_
#define    _CertificatePolicies_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PolicyInformation;

/* CertificatePolicies */
typedef struct CertificatePolicies {
    A_SEQUENCE_OF(struct PolicyInformation) list;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertificatePolicies_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificatePolicies_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificatePolicies_desc(void);

#ifdef __cplusplus
}
#endif

#endif
