/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_ECDSA_H
#define CRYPTONITE_ECDSA_H

#include <stdbool.h>

#include "byte_array.h"
#include "prng.h"
#include "opt_level.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ECDSA.
 */
typedef struct EcdsaCtx_st EcdsaCtx;

/**
 * Iдентифікатори стандартних параметрів ECDSA.
 */
typedef enum {
    ECDSA_PARAMS_ID_SEC_P192_R1 = 1,
    ECDSA_PARAMS_ID_SEC_P224_R1 = 2,
    ECDSA_PARAMS_ID_SEC_P256_R1 = 3,
    ECDSA_PARAMS_ID_SEC_P384_R1 = 4,
    ECDSA_PARAMS_ID_SEC_P521_R1 = 5,
    ECDSA_PARAMS_ID_SEC_P256_K1 = 6
} EcdsaParamsId;

/**
 * Створює контекст ECDSA зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст ECDSA
 */
CRYPTONITE_EXPORT EcdsaCtx *ecdsa_alloc(EcdsaParamsId params_id);

/**
 * Створює контекст ECDSA за параметрами.
 *
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 *
 * @return контекст ECDSA
 */
CRYPTONITE_EXPORT EcdsaCtx *ecdsa_alloc_ext(const ByteArray *p, const ByteArray *a, const ByteArray *b,
                                            const ByteArray *q, const ByteArray *px, const ByteArray *py);

/**
 * Повертає параметри ECDSA.
 *
 * @param ctx контекст ECDSA
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_get_params(EcdsaCtx *ctx, ByteArray **p, ByteArray **a, ByteArray **b, ByteArray **q,
                                       ByteArray **px, ByteArray **py);

/**
 * Визначає чи параметри однакові ECDSA.
 *
 * @param param_a контекст ECDSA
 * @param param_b контекст ECDSA
 * @param equals чи параметри однакові
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_equals_params(const EcdsaCtx *param_a, const EcdsaCtx *param_b, bool *equals);

/**
 * Копіює параметри ECDSA.
 *
 * @param param контекст ECDSA
 * @return контекст ECDSA
 */
CRYPTONITE_EXPORT EcdsaCtx *ecdsa_copy_params_with_alloc(const EcdsaCtx *param);

/**
 * Копіює контекст ECDSA.
 *
 * @param param контекст ECDSA
 * @return контекст ECDSA
 */
CRYPTONITE_EXPORT EcdsaCtx *ecdsa_copy_with_alloc(const EcdsaCtx *param);

/**
 * Генерує закритий ключ ECDSA.
 *
 * @param ctx контекст ECDSA
 * @param prng контекст ГПСЧ
 * @param d закритий ключ ECDSA
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_generate_privkey(EcdsaCtx *ctx, PrngCtx *prng, ByteArray **d);

/**
 * Формує відкритий ключ по закритому.
 *
 * @param ctx контекст ECDSA
 * @param d закритий ключ
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_get_pubkey(EcdsaCtx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy);

CRYPTONITE_EXPORT int ecdsa_compress_pubkey(EcdsaCtx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q,
                                            int *last_qy_bit);

CRYPTONITE_EXPORT int ecdsa_decompress_pubkey(EcdsaCtx *ctx, const ByteArray *q, int last_qy_bit, ByteArray **qx,
                                              ByteArray **qy);

CRYPTONITE_EXPORT int ecdsa_set_opt_level(EcdsaCtx *ctx, OptLevelId opt_level);

/**
 * Ініціалізує контекст для формування підпису.
 *
 * @param ctx контекст ECDSA
 * @param d закритий ключ
 * @param prng контекст ГПСЧ
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_init_sign(EcdsaCtx *ctx, const ByteArray *d, PrngCtx *prng);

/**
 * Формує підпис по гешу.
 *
 * @param ctx контекст ECDSA
 * @param hash геш
 * @param r частина підпису
 * @param s частина підпису
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_sign(EcdsaCtx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s);

/**
 * Ініціалізує контекст для перевірки підпису.
 *
 * @param ctx контекст ECDSA
 * @param qx Х-координата відкритого ключа
 * @param qy Y-координата відкритого ключа
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecdsa_init_verify(EcdsaCtx *ctx, const ByteArray *qx, const ByteArray *qy);

/**
 * Виконує перевірку підпису по гешу від даних.
 *
 * @param ctx контекст ECDSA
 * @param hash геш
 * @param r частина підпису
 * @param s частина підпису
 *  * @return код помилки або RET_OK, якщо підпис вірний
 */
CRYPTONITE_EXPORT int ecdsa_verify(EcdsaCtx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s);

/**
 * Звільняє контекст ECDSA.
 *
 * @param ctx контекст ECDSA
 *
 */
CRYPTONITE_EXPORT void ecdsa_free(EcdsaCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
