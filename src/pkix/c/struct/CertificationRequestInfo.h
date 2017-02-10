/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _CertificationRequestInfo_H_
#define    _CertificationRequestInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Version.h"
#include "Name.h"
#include "SubjectPublicKeyInfo.h"
#include "Attributes.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificationRequestInfo */
typedef struct CertificationRequestInfo {
    Version_t     version;
    Name_t     subject;
    SubjectPublicKeyInfo_t     subjectPKInfo;
    Attributes_t     attributes;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} CertificationRequestInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t CertificationRequestInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_CertificationRequestInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
