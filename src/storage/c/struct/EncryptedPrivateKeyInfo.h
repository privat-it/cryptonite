/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _EncryptedPrivateKeyInfo_H_
#define    _EncryptedPrivateKeyInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EncryptedPrivateKeyInfo */
typedef struct EncryptedPrivateKeyInfo {
    AlgorithmIdentifier_t     encryptionAlgorithm;
    OCTET_STRING_t     encryptedData;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} EncryptedPrivateKeyInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t EncryptedPrivateKeyInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_EncryptedPrivateKeyInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
