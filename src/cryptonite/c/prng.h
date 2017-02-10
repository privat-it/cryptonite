/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef PRNG_H
#define PRNG_H

#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст ГПВЧ.
 */
typedef struct PrngCtx_st PrngCtx;

typedef enum {
    PRNG_MODE_DEFAULT = 0,
    PRNG_MODE_DSTU = 1
} PrngMode;

/**
 * Створює контекст ГПВЧ.
 *
 * @param mode режим ГПВЧ
 * @param seed послідовність випадкових байт
 * @return контекст ГПВЧ
 */
CRYPTONITE_EXPORT PrngCtx *prng_alloc(PrngMode mode, const ByteArray *seed);

CRYPTONITE_EXPORT int prng_get_mode(PrngCtx *prng, PrngMode *mode);

/**
 * Домішує випадковість у стартовий вектор генератора.
 *
 * @param prng контекст ГПВЧ
 * @param seed послідовність випадкових байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int prng_seed(PrngCtx *prng, const ByteArray *seed);

/**
 * Повертає масив псевдовипадкових байт.
 *
 * @param prng контекст генерації псевдовипдкових чисел
 * @param buf буфер, в якому будуть розміщені псевдовипадкові байти
 * @return код помилки
 */
CRYPTONITE_EXPORT int prng_next_bytes(PrngCtx *prng, ByteArray *buf);

/**
 * Звільняє контекст ГПВЧ.
 *
 * @param prng контекст ГПВЧ
 */
CRYPTONITE_EXPORT void prng_free(PrngCtx *prng);

#ifdef __cplusplus
}
#endif

#endif
