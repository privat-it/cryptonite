/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EncryptedData_H_
#define    _EncryptedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "EncryptedContentInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attributes;

/* EncryptedData */
typedef struct EncryptedData {
    CMSVersion_t     version;
    EncryptedContentInfo_t     encryptedContentInfo;
    struct Attributes    *unprotectedAttrs    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EncryptedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t EncryptedData_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EncryptedData_desc(void);

#ifdef __cplusplus
}
#endif

#endif
