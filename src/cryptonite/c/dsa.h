/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSA_H
#define CRYPTONITE_DSA_H

#include "prng.h"
#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст DSA.
 */
typedef struct DsaCtx_st DsaCtx;

/**
 * Створює контекст DSA.
 *
 * @param p порядок простого скінченного поля GF(p)
 * @param q порядок простого скінченного поля GF(q)
 * @param g елемент простого скінченного поля GF(p)
 * @return контекст DSA
 */
CRYPTONITE_EXPORT DsaCtx *dsa_alloc(const ByteArray *p, const ByteArray *q, const ByteArray *g);

CRYPTONITE_EXPORT DsaCtx *dsa_alloc_ext(int l, int n, PrngCtx *prng);

/**
 * Повертає параметри DSA
 *
 * @param ctx контекст DSA
 * @param p порядок простого скінченного поля GF(p)
 * @param q порядок простого скінченного поля GF(q)
 * @param g елемент простого скінченного поля GF(p)
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_get_params(const DsaCtx *ctx, ByteArray **p, ByteArray **q, ByteArray **g);

/**
 * Генерує ключову пару для DSA.
 *
 * @param ctx контекст DSA
 * @param prng контекст ГПСЧ
 * @param priv_key закритий ключ DSA
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_generate_privkey(const DsaCtx *ctx, PrngCtx *prng, ByteArray **priv_key);

/**
 * Формує відкритий ключ за закритим.
 *
 * @param ctx контекст DSA
 * @param priv_key закритий ключ
 * @param pub_key відкритий ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_get_pubkey(const DsaCtx *ctx, const ByteArray *priv_key, ByteArray **pub_key);

/**
 * Ініціалізує контекст із закритим ключем.
 *
 * @param ctx контекст DSA
 * @param priv_key закритий ключ
 * @param prng контекст ГПСЧ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_init_sign(DsaCtx *ctx, const ByteArray *priv_key, PrngCtx *prng);

/**
 * Підписує повідомлення.
 *
 * @param ctx контекст DSA
 * @param hash геш дані
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_sign(const DsaCtx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s);

/**
 * Ініціалізує контекст з відкритим ключем.
 *
 * @param ctx контекст DSA
 * @param pub_key відкритий ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dsa_init_verify(DsaCtx *ctx, const ByteArray *pub_key);

/**
 * Перевіряє повідомлення.
 *
 * @param ctx контекст DSA
 * @param hash геш дані
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки або RET_OK, якщо підпис вірний
 */
CRYPTONITE_EXPORT int dsa_verify(const DsaCtx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s);

/**
 * Звільняє контекст DSA.
 *
 * @param ctx контекст DSA
 */
CRYPTONITE_EXPORT void dsa_free(DsaCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
