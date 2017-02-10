/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
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
 * @param seed_len розмір послідовності випадкових байт
 * @return контекст ГПВЧ
 */
Dstu4145PrngCtx *dstu4145_prng_alloc(const ByteArray *seed);

/**
 * Домішуе випадковість у стартовий вектор генератора.
 *
 * @param prng контекст ГПВЧ
 * @param seed послідовність випадкових байт
 * @param seed_len розмір послідовності випадкових байт
 * @return код помилки
 */
int dstu4145_prng_seed(Dstu4145PrngCtx *prng, const ByteArray *seed);

/**
 * Повертає массив псевдовипадкових байт.
 *
 * @param prng контекст генерації псевдовипадкових чисел
 * @param buf буфер, у якому будуть розміщено псевдовипадкові байти
 * @param buf_len розмір буфера у байтах
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
