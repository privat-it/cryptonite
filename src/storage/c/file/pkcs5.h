/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __STORAGE_PKCS5_H__
#define __STORAGE_PKCS5_H__

#include "byte_array.h"
#include "pkix_structs.h"

#include "EncryptedPrivateKeyInfo.h"

typedef enum Pkcs5Type_st {
    PKCS5_UNKNOWN = 0,
    PKCS5_IIT = 1,
    PKCS5_DSTU = 2,
} Pkcs5Type;

CRYPTONITE_EXPORT int pkcs5_get_type(const EncryptedPrivateKeyInfo_t *container, Pkcs5Type *type);

CRYPTONITE_EXPORT int pkcs5_decrypt_dstu(const EncryptedPrivateKeyInfo_t *container, const char *pass, ByteArray **key);

CRYPTONITE_EXPORT int pkcs5_encrypt_dstu(const ByteArray *key, const char *pass, const ByteArray *salt,
        unsigned long iterations,
        const AlgorithmIdentifier_t *encrypt_aid, EncryptedPrivateKeyInfo_t **container);

#endif
