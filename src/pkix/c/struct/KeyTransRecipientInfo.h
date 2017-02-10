/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyTransRecipientInfo_H_
#define    _KeyTransRecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "RecipientIdentifier.h"
#include "KeyEncryptionAlgorithmIdentifier.h"
#include "EncryptedKey.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyTransRecipientInfo */
typedef struct KeyTransRecipientInfo {
    CMSVersion_t     version;
    RecipientIdentifier_t     rid;
    KeyEncryptionAlgorithmIdentifier_t     keyEncryptionAlgorithm;
    EncryptedKey_t     encryptedKey;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} KeyTransRecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyTransRecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyTransRecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
