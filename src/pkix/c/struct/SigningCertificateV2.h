/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _SigningCertificateV2_H_
#define    _SigningCertificateV2_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ESSCertIDv2;
struct PolicyInformation;

/* SigningCertificateV2 */
typedef struct SigningCertificateV2 {
    struct certs {
        A_SEQUENCE_OF(struct ESSCertIDv2) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } certs;
    struct policies {
        A_SEQUENCE_OF(struct PolicyInformation) list;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } *policies;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} SigningCertificateV2_t;

/* Implementation */
extern asn_TYPE_descriptor_t SigningCertificateV2_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_SigningCertificateV2_desc(void);

#ifdef __cplusplus
}
#endif

#endif
