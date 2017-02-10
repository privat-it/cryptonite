/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _PasswordRecipientInfo_H_
#define    _PasswordRecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "KeyEncryptionAlgorithmIdentifier.h"
#include "EncryptedKey.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct AlgorithmIdentifier;

/* PasswordRecipientInfo */
typedef struct PasswordRecipientInfo {
    CMSVersion_t     version;
    struct AlgorithmIdentifier    *keyDerivationAlgorithm    /* OPTIONAL */;
    KeyEncryptionAlgorithmIdentifier_t     keyEncryptionAlgorithm;
    EncryptedKey_t     encryptedKey;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} PasswordRecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t PasswordRecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_PasswordRecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
