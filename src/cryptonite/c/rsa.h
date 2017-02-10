/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_RSA_H
#define CRYPTONITE_RSA_H

#include <stdbool.h>

#include "byte_array.h"
#include "prng.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    RSA_HASH_SHA1 = 0,
    RSA_HASH_SHA256 = 1,
    RSA_HASH_SHA384 = 2,
    RSA_HASH_SHA512 = 3
} RsaHashType;

/**
 * Контекст RSA.
 */
typedef struct RsaCtx_st RsaCtx;

/**
 * Створює контекст RSA.
 *
 * @return контекст RSA
 */
CRYPTONITE_EXPORT RsaCtx *rsa_alloc(void);

/**
 * Генерує закритий ключ RSA.
 *
 * @param ctx контекст RSA
 * @param prng ГПВЧ
 * @param bits бітність ключа
 * @param e відкрита експонента
 * @param n модуль
 * @param d секретна експонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_generate_privkey(RsaCtx *ctx, PrngCtx *prng, const size_t bits, const ByteArray *e,
        ByteArray **n, ByteArray **d);

/**
 * Генерує закритий ключ RSA.
 *
 * @param ctx контекст RSA
 * @param prng ГПВЧ
 * @param bits бітність ключа
 * @param e відкрита експонента
 * @param n модуль
 * @param d закрита експонента
 * @param p просте число №1
 * @param q просте число №2
 * @param dmp1 d mod (p-1)
 * @param dmq1 d mod (q-1)
 * @param iqmp зворотній елемент q
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_generate_privkey_ext(RsaCtx *ctx, PrngCtx *prng, const size_t bits, const ByteArray *e,
        ByteArray **n, ByteArray **d, ByteArray **p, ByteArray **q, ByteArray **dmp1, ByteArray **dmq1, ByteArray **iqmp);

/**
 * Перевіряє закритий ключ RSA.
 *
 * @param ctx контекст RSA
 * @param n модуль
 * @param e відкрита експонента
 * @param d закрита експонента
 * @param p просте число №1
 * @param q просте число №2
 * @param dmp1 d mod (p-1)
 * @param dmq1 d mod (q-1)
 * @param iqmp зворотній елемент q
 * @return код помилки
 */
CRYPTONITE_EXPORT bool rsa_validate_key(RsaCtx *ctx, const ByteArray *n, const ByteArray *e, const ByteArray *d,
        const ByteArray *p, const ByteArray *q, const ByteArray *dmp1, const ByteArray *dmq1, const ByteArray *iqmp);

/**
 * Ініціалізація контексту RSA для режиму OAEP.
 *
 * @param ctx контекст RSA
 * @param prng ГПВЧ
 * @param htype вибір геша. Береться з RsaHashType
 * @param label необов'язкова мітка, яка асоціюється з повідомленням;
 * значення за замовчуванням - пустий рядок
 * @param n модуль
 * @param e відкрита експонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_encrypt_oaep(RsaCtx *ctx, PrngCtx *prng, RsaHashType htype, ByteArray *label,
        const ByteArray *n, const ByteArray *e);

/**
 * Ініціалізація контексту RSA для режиму OAEP.
 *
 * @param ctx контекст RSA
 * @param htype вибір геша. Береться з RsaHashType
 * @param label необов'язкова мітка, яка асоціюється з повідомленням;
 * значення за замовчуванням - пустий рядок
 * @param n модуль
 * @param d закрита экспонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_decrypt_oaep(RsaCtx *ctx, RsaHashType htype, ByteArray *label, const ByteArray *n,
        const ByteArray *d);

/**
 * Ініціалізація контексту RSA для режиму PKCS1_5.
 *
 * @param ctx контекст RSA
 * @param prng ГПВЧ
 * @param n модуль
 * @param e відкрита експонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_encrypt_pkcs1_v1_5(RsaCtx *ctx, PrngCtx *prng, const ByteArray *n, const ByteArray *e);

/**
 * Ініціалізація контексту RSA для режиму PKCS1_5.
 *
 * @param ctx контекст RSA
 * @param n модуль
 * @param d закрита экспонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *d);

/**
 * Шифрування даних.
 *
 * @param ctx контекст RSA
 * @param data дані для шифрування
 * @param encrypted_data зашифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_encrypt(RsaCtx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування даних.
 *
 * @param ctx контекст RSA
 * @param encrypted_data дані для розшифрування
 * @param data розшифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_decrypt(RsaCtx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Ініціалізує контекст RSA для формування ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash_type тип геша
 * @param n модуль
 * @param d закрита експонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_sign_pkcs1_v1_5(RsaCtx *ctx, RsaHashType hash_type, const ByteArray *n,
        const ByteArray *d);

/**
 * Формує ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash значення геша
 * @param sign підпис RSA
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_sign_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *hash, ByteArray **sign);

/**
 * Ініціалізує контекст RSA для перевірки ЕЦП згідно з PKCS№1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash_type тип геша
 * @param n модуль
 * @param e відкрита экспонента
 * @return код помилки
 */
CRYPTONITE_EXPORT int rsa_init_verify_pkcs1_v1_5(RsaCtx *ctx, RsaHashType hash_type, const ByteArray *n,
        const ByteArray *e);

/**
 * Перевіряє ЕЦП згідно з PKCS#1 v2.1 “RSA  Cryptography  Standard” RSASSA-PKCS1-v1_5.
 *
 * @param ctx контекст RSA
 * @param hash значення геша
 * @param sign підпис RSA
 * @return код помилки або RET_OK, якщо підпис вірний
 */
CRYPTONITE_EXPORT int rsa_verify_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *hash, const ByteArray *sign);

/**
 * Звільняє контекст RSA.
 *
 * @param ctx
 */
CRYPTONITE_EXPORT void rsa_free(RsaCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
