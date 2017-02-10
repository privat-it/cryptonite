/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DES_H
#define CRYPTONITE_DES_H

#include "byte_array.h"
#include "prng.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст DES.
 */
typedef struct DesCtx_st DesCtx;

/**
 * Створює контекст DES.
 *
 * @return контекст DES
 */
CRYPTONITE_EXPORT DesCtx *des_alloc(void);

/**
 * Генерує секретний ключ.
 *
 * @param prng контекст ГПСЧ
 * @param key_len размер ключа 8, 16 или 24
 * @param key секретний ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_generate_key(PrngCtx *prng, size_t key_len, ByteArray **key);

/**
 * Ініціалізація контексту DES для режиму ECB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_init_ecb(DesCtx *ctx, const ByteArray *key);

/**
 * Ініціалізація контексту DES для режиму CBC.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_init_cbc(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму CFB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_init_cfb(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму OFB.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_init_ofb(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізація контексту DES для режиму CTR.
 *
 * @param ctx контекст DES
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_init_ctr(DesCtx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Шифрування у режимі DES.
 *
 * @param ctx контекст DES
 * @param data розшифровані дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_encrypt(DesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі DES.
 *
 * @param ctx контекст DES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int des_decrypt(DesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Шифрування у режимі TDES EDE.
 *
 * @param ctx контекст DES
 * @param data розшифровані дані
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int des3_encrypt(DesCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування у режимі TDES EDE.
 *
 * @param ctx контекст DES
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int des3_decrypt(DesCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Звільняє контекст DES.
 *
 * @param ctx контекст DES
 */
CRYPTONITE_EXPORT void des_free(DesCtx *ctx);

#ifdef __cplusplus
}
#endif

#endif
