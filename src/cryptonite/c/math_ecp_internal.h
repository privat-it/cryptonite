/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Арифметика групи точок еліптичної кривої над простим полем GF(p):
 *
 *     y^2 = x^3 + a*x + b (mod p).
 *
 * Внутрішні обчислення ведуться у якобіанських проєктивних координатах
 * (x = X/Z^2, y = Y/Z^3), що дозволяє уникати ділення в полі при додаванні
 * та подвоєнні точок; обернений елемент обчислюється один раз при
 * фінальному переході до афінних координат. Точка на нескінченності
 * подається трійкою (0, 0, 1).
 *
 * Скалярне множення: базове (double-and-add) та оптимізоване з таблицями
 * попередніх обчислень — віконний метод з NAF-розкладанням скаляра або
 * метод гребеня (див. math_ec_precomp_internal.h, opt_level.h).
 *
 * Модуль використовується реалізаціями ECDSA та ГОСТ 34.310.
 */

#ifndef CRYPTONITE_MATH_ECP_H
#define CRYPTONITE_MATH_ECP_H

#include <stdbool.h>

#include "math_ec_point_internal.h"
#include "math_ec_precomp_internal.h"
#include "math_gfp_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

/** Контекст для работы з группой точек еліптичної кривої. */
typedef struct EcGfpCtx_st {
    GfpCtx *gfp;            /* Контекст поля GF(p). */
    WordArray *a;              /* коефіцієнт еліптичної кривої a. */
    WordArray *b;           /* коефіцієнт еліптичної кривої b. */
    bool a_equal_minus_3;   /* Ознака a == -3 (mod p): вмикає швидшу формулу подвоєння точки. */
    size_t len;             /* Довжина елементів поля у машинних словах. */
} EcGfpCtx;

/**
 * Створює контекст еліптичної кривої над GF(p).
 *
 * @param p модуль простого поля
 * @param a коефіцієнт a еліптичної кривої
 * @param b коефіцієнт b еліптичної кривої
 * @return контекст еліптичної кривої або NULL у разі помилки
 */
EcGfpCtx *ecp_alloc(const WordArray *p, const WordArray *a, const WordArray *b);

/**
 * Ініціалізує контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param p порядок кінцевого просте поля
 * @param a коефіцієнт a еліптичної кривої
 * @param b коефіцієнт b еліптичної кривої
 */
void ecp_init(EcGfpCtx *ctx, const WordArray *p, const WordArray *a, const WordArray *b);

/**
 * Створює копію контексту еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @return копія контексту або NULL у разі помилки
 */
EcGfpCtx *ecp_copy_with_alloc(EcGfpCtx *ctx);

/**
 * Перевіряє принадлежность точки еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точки еліптичної кривої
 * @param py y-координата точки еліптичної кривої
 *
 * @return true - точка лежит на кривої,
 *         false - точка не лежит на кривої
 */
bool ecp_is_on_curve(const EcGfpCtx *ctx, const WordArray *px, const WordArray *py);

/**
 * Умножает точку еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param r результат скалярного умножения
 */
void ecp_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r);


/**
 * Умножает точку (одновременно две точки) еліптичної кривої на число.
 *
 * Заранее должны бути рассчитаны предварительные обчислення для
 * метода гребня або скользящйого окна для каждой точки P і Q.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param q точка Q
 * @param n число на яке умножается q
 * @param r = m * P + n * Q
 */
void ecp_dual_mul(EcGfpCtx *ctx, const ECPoint *p, const WordArray *k,
        const ECPoint *q, const WordArray *n, ECPoint *r);

/**
 * Рассчитывает предобчислення для оконного метода умножения точки на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точки еліптичної кривої
 * @param py y-координата точки еліптичної кривої
 * @param w ширина окна
 * @param precomp_p буфер для передвичесленням розміра 2^(w - 2) * 2 * sizeof(p)
 *
 * @return код помилки
 */
int ecp_calc_win_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Рассчитывает предобчислення для метода гребня.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точка еліптичної кривої
 * @param py y-координата точка еліптичної кривої
 * @param w ширина окна
 * @param precomp_p предварительные обчислення
 *
 * @return код помилки
 */
int ecp_calc_comb_precomp(EcGfpCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Умножает точку (одновременно две точки) еліптичної кривої на число.
 *
 * Заранее должны бути рассчитаны предварительные обчислення для
 * метода гребня або скользящйого окна для каждой точки P і Q.
 *
 * @param ctx контекст еліптичної кривої
 * @param precomp_p предварительные обчислення для точки P
 * @param m число на яке умножается p
 * @param precomp_q предварительные обчислення для точки Q
 * @param n число на яке умножается q
 * @param r = m * P + n * Q
 */
int ecp_dual_mul_opt(EcGfpCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r);

/**
 * Звільняє контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 */
void ecp_free(EcGfpCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
