/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_CRYPTO_CACHE_H
#define CRYPTONITE_CRYPTO_CACHE_H

#include "byte_array.h"
#include "dstu4145.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Додає до кешу контекст ДСТУ 4145 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crypto_cache_add_dstu4145(Dstu4145ParamsId params_id, OptLevelId opt_level);

/**
 * Додає до кешу контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
 *
 * @param f примітивний многочлен f(t) (тричлен, п'ятичлен), який визначає поліноміальний базис
 * @param f_len число членів у полиномі f (3 або 5)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crypto_cache_add_dstu4145_pb(const int *f, size_t f_len, int a, const ByteArray *b,
        const ByteArray *n,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Додає до кешу контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
 *
 * @param m степінь основного поля, непарне просте число (163 <= m <= 509)
 * @param a коефіцієнт у рівнянні еліптичної кривої (0 або 1)
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param n порядок циклічної підгрупи групи точок еліптичної кривої
 * @param px X-координата точки еліптичної кривої порядока n
 * @param py Y-координата точки еліптичної кривої порядока n
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crypto_cache_add_dstu4145_onb(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Додає до кешу контекст ECDSA.
 *
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crypto_cache_add_ecdsa(const ByteArray *p, const ByteArray *a, const ByteArray *b,
        const ByteArray *q,
        const ByteArray *px, const ByteArray *py, OptLevelId opt_level);

/**
 * Додає до кешу контекст будь який новий контекст ДСТУ 4145 та ECDSA.
 *
 * @param opt_level рівень передобчислення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crypto_cache_add_any_new(OptLevelId opt_level);

/**
 * Звільняє контекст кеша крипто контекстів.
 */
CRYPTONITE_EXPORT void crypto_cache_free(void);

#ifdef  __cplusplus
}
#endif

#endif
