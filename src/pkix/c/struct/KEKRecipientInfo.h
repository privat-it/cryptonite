/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _KEKRecipientInfo_H_
#define    _KEKRecipientInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CMSVersion.h"
#include "KEKIdentifier.h"
#include "KeyEncryptionAlgorithmIdentifier.h"
#include "EncryptedKey.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KEKRecipientInfo */
typedef struct KEKRecipientInfo {
    CMSVersion_t     version;
    KEKIdentifier_t     kekid;
    KeyEncryptionAlgorithmIdentifier_t     keyEncryptionAlgorithm;
    EncryptedKey_t     encryptedKey;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} KEKRecipientInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t KEKRecipientInfo_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_KEKRecipientInfo_desc(void);

#ifdef __cplusplus
}
#endif

#endif
