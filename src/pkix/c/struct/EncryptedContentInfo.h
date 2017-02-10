/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EncryptedContentInfo_H_
#define    _EncryptedContentInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ContentType.h"
#include "ContentEncryptionAlgorithmIdentifier.h"
#include "EncryptedContent.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EncryptedContentInfo */
typedef struct EncryptedContentInfo {
    ContentType_t     contentType;
    ContentEncryptionAlgorithmIdentifier_t     contentEncryptionAlgorithm;
    EncryptedContent_t    *encryptedContent    /* OPTIONAL */;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EncryptedContentInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t EncryptedContentInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EncryptedContentInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
