/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __STORAGE_PKCS5_H__
#define __STORAGE_PKCS5_H__

/**
 * @addtogroup storage
 * @{
 */

#include "byte_array.h"
#include "pkix_structs.h"

#include "EncryptedPrivateKeyInfo.h"

typedef enum Pkcs5Type_st {
    PKCS5_UNKNOWN = 0,
    PKCS5_IIT = 1,
    PKCS5_DSTU = 2,
} Pkcs5Type;

typedef enum Pbkdf2HmacId_st {
    PBKDF2_GOST_HMAC_ID = 0,
    PBKDF2_SHA1_HMAC_ID = 1,
    PBKDF2_SHA224_HMAC_ID = 2,
    PBKDF2_SHA256_HMAC_ID = 3,
    PBKDF2_SHA384_HMAC_ID = 4,
    PBKDF2_SHA512_HMAC_ID = 5
} Pbkdf2HmacId;

/**
 * Визначає тип PKCS#5 контейнера.
 *
 * @param container контейнер зашифрованого закритого ключа
 * @param type      тип PKCS#5
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs5_get_type(const EncryptedPrivateKeyInfo_t *container, Pkcs5Type *type);

/**
 * Розшифровує закритий ключ за схемою PBES2 (PKCS#5).
 *
 * @param container контейнер зашифрованого закритого ключа
 * @param pass      пароль
 * @param key       розшифрований вміст
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs5_decrypt_dstu(const EncryptedPrivateKeyInfo_t *container, const char *pass, ByteArray **key);

/**
 * Шифрує ключ за схемою PBES2 (PKCS#5).
 *
 * @param key         дані, що шифруються
 * @param pass        пароль
 * @param salt        сіль для деривації ключа
 * @param iterations  кількість ітерацій деривації
 * @param encrypt_aid алгоритм шифрування вмісту
 * @param container   сформований EncryptedPrivateKeyInfo
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs5_encrypt_dstu(const ByteArray *key, const char *pass, const ByteArray *salt,
        unsigned long iterations,
        const AlgorithmIdentifier_t *encrypt_aid, EncryptedPrivateKeyInfo_t **container);

/** @} */

#endif
