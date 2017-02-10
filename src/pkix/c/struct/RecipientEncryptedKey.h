/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef    _RecipientEncryptedKey_H_
#define    _RecipientEncryptedKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "KeyAgreeRecipientIdentifier.h"
#include "EncryptedKey.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RecipientEncryptedKey */
typedef struct RecipientEncryptedKey {
    KeyAgreeRecipientIdentifier_t     rid;
    EncryptedKey_t     encryptedKey;

    /* Context for parsing across buffer boundaries */
    asn_struct_ctx_t _asn_ctx;
} RecipientEncryptedKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t RecipientEncryptedKey_desc;
CRYPTONITE_EXPORT asn_TYPE_descriptor_t *get_RecipientEncryptedKey_desc(void);

#ifdef __cplusplus
}
#endif

#endif
