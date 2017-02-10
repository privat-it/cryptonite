/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _TBSCertList_H_
#define    _TBSCertList_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "AlgorithmIdentifier.h"
#include "Name.h"
#include "PKIXTime.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RevokedCertificates;
struct Extensions;

/* TBSCertList */
typedef struct TBSCertList {
    Version_t    *version    /* OPTIONAL */;
    AlgorithmIdentifier_t     signature;
    Name_t     issuer;
    PKIXTime_t     thisUpdate;
    PKIXTime_t     nextUpdate;
    struct RevokedCertificates    *revokedCertificates    /* OPTIONAL */;
    struct Extensions    *crlExtensions    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} TBSCertList_t;

/* Implementation */
extern asn_TYPE_descriptor_t TBSCertList_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_TBSCertList_desc(void);

#ifdef __cplusplus
}
#endif

#endif
