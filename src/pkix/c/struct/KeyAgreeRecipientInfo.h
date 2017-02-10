/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KeyAgreeRecipientInfo_H_
#define    _KeyAgreeRecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "OriginatorIdentifierOrKey.h"
#include "UserKeyingMaterial.h"
#include "KeyEncryptionAlgorithmIdentifier.h"
#include "RecipientEncryptedKeys.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyAgreeRecipientInfo */
typedef struct KeyAgreeRecipientInfo {
    CMSVersion_t     version;
    OriginatorIdentifierOrKey_t     originator;
    UserKeyingMaterial_t    *ukm    /* OPTIONAL */;
    KeyEncryptionAlgorithmIdentifier_t     keyEncryptionAlgorithm;
    RecipientEncryptedKeys_t     recipientEncryptedKeys;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} KeyAgreeRecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t KeyAgreeRecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KeyAgreeRecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
