/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _AuthorityKeyIdentifier_H_
#define    _AuthorityKeyIdentifier_H_


#include "asn_application.h"

/* Including external dependencies */
#include "KeyIdentifier.h"
#include "CertificateSerialNumber.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct GeneralNames;

/* AuthorityKeyIdentifier */
typedef struct AuthorityKeyIdentifier {
    KeyIdentifier_t    *keyIdentifier    /* OPTIONAL */;
    struct GeneralNames    *authorityCertIssuer    /* OPTIONAL */;
    CertificateSerialNumber_t    *authorityCertSerialNumber    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} AuthorityKeyIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t AuthorityKeyIdentifier_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_AuthorityKeyIdentifier_desc(void);

#ifdef __cplusplus
}
#endif

#endif
