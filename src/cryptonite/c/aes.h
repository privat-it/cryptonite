/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_AES_H
#define CRYPTONITE_AES_H

#include "byte_array.h"
#include "prng.h"


#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст AES.
 */
typedef struct AesCtx_st AesCtx;

/**
 * Створює контекст AES.
 *
 * @return контекст AES
 */
CRYPTONITE_EXPORT AesCtx *aes_alloc(void);

/**
 * Генерує секретний ключ.
 *
 * @param prng контекст ГПСЧ
 * @param key_len размер ключа 16, 24 или 32
 * @param key секретний ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_generate_key(PrngCtx *prng, size_t key_len, ByteArray **key);

/**
 * Ініціалізація контексту AES для режиму ECB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_init_ecb(AesCtx *ctx, const ByteArray *key);

/**
 * Ініціалізація контексту AES для режиму CBC.
 * Розмір даних при шифруванні/розшифруванні повинет бути кратен розміру блока AES (16 байт),
 * окрім останнього блоку при шифруванні.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_init_cbc(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму CFB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_init_cfb(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму OFB.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_init_ofb(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту AES для режиму CTR.
 *
 * @param ctx контекст AES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_init_ctr(AesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Шифрування у режимі AES.
 *
 * @param ctx контекст AES
 * @param data дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_encrypt(AesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі AES.
 *
 * @param ctx контекст AES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int aes_decrypt(AesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Звільняє контекст AES.
 *
 * @param ctx контекст AES
 */
CRYPTONITE_EXPORT void aes_free(AesCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
