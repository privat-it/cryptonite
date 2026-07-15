/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Внутрішній інтерфейс ГПВЧ за схемою ДСТУ 4145
 * (реалізація — dstu4145_prng_internal.c; генератор на основі
 * ГОСТ 28147-89 із домішуванням випадковості через ГОСТ 34.311).
 * Використовується публічною обгорткою prng.h/prng.c.
 */

#ifndef CRYPTONITE_RANDOM_H
#define CRYPTONITE_RANDOM_H

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГПВЧ ДСТУ 4145.
 */
typedef struct Dstu4145Prng_st Dstu4145PrngCtx;

/**
 * Створює контекст ГПВЧ.
 *
 * @param seed послідовність з мінімум 40 випадкових байт
 * @return контекст ГПВЧ або NULL у разі помилки
 */
Dstu4145PrngCtx *dstu4145_prng_alloc(const ByteArray *seed);

/**
 * Домішує випадковість у внутрішній стан генератора.
 *
 * @param prng контекст ГПВЧ
 * @param seed послідовність випадкових байт
 * @return код помилки
 */
int dstu4145_prng_seed(Dstu4145PrngCtx *prng, const ByteArray *seed);

/**
 * Повертає масив псевдовипадкових байт.
 *
 * @param prng контекст генерації псевдовипадкових чисел
 * @param buf буфер, у якому буде розміщено псевдовипадкові байти
 *            (заповнюється повністю, buf->len байт)
 * @return код помилки
 */
int dstu4145_prng_next_bytes(Dstu4145PrngCtx *prng, ByteArray *buf);

/**
 * Звільняє контекст ГПВЧ ДСТУ 4145.
 *
 * @param prng контекст ГПВЧ ДСТУ 4145
 */
void dstu4145_prng_free(Dstu4145PrngCtx *prng);

#ifdef  __cplusplus
}
#endif

#endif
