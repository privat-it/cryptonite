/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RevokedCertificate_H_
#define    _RevokedCertificate_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CertificateSerialNumber.h"
#include "PKIXTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Extensions;

/* RevokedCertificate */
typedef struct RevokedCertificate {
    CertificateSerialNumber_t     userCertificate;
    PKIXTime_t     revocationDate;
    struct Extensions    *crlEntryExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RevokedCertificate_t;

/* Implementation */
extern asn_TYPE_descriptor_t RevokedCertificate_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RevokedCertificate_desc(void);

#ifdef __cplusplus
}
#endif

#endif
