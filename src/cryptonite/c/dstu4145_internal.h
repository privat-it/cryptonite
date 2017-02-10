/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU4145_INTERNAL_H
#define CRYPTONITE_DSTU4145_INTERNAL_H

#include "dstu4145.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Створює контекст ДСТУ 4145 зі стандартними параметрами.
 *
 * @param params_id ідентифікатор стандартних параметрів
 * @return контекст ДСТУ 4145
 */
Dstu4145Ctx *dstu4145_alloc_new(Dstu4145ParamsId params_id);

/**
 * Створює контекст ДСТУ 4145 з параметрами у поліноміальному базисі.
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
Dstu4145Ctx *dstu4145_alloc_pb_new(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py);

/**
 * Створює контекст ДСТУ 4145 з параметрами у оптимальному нормальному базисі.
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
Dstu4145Ctx *dstu4145_alloc_onb_new(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py);

#ifdef  __cplusplus
}
#endif

#endif
