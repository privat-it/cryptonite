/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_CRYPTO_CACHE_INTERNAL_H
#define CRYPTONITE_CRYPTO_CACHE_INTERNAL_H

#include "byte_array.h"
#include "ecdsa.h"
#include "dstu4145.h"
#include "word_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

extern OptLevelId default_opt_level;

/**
 * Шукає в кеші контекст ДСТУ 4145 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 *
 * @return контекст ДСТУ 4145
 */
Dstu4145Ctx *crypto_cache_get_dstu4145(Dstu4145ParamsId params_id);

/**
 * Шукає в кеші контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
 *
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return контекст ДСТУ 4145
 */
Dstu4145Ctx *crypto_cache_get_dstu4145_pb(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py);

/**
 * Шукає в кеші контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
 *
 * @param m степінь основного поля, непарне просте число (163 <= m <= 509)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return контекст ДСТУ 4145
 */
Dstu4145Ctx *crypto_cache_get_dstu4145_onb(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py);

/**
 * Шукає в кеші контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
 *
 * @param p
 * @param a
 * @param b
 * @param q
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 *
 * @return контекст ДСТУ 4145
 */
EcdsaCtx *crypto_cache_get_ecdsa(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py);


#ifdef  __cplusplus
}
#endif

#endif
