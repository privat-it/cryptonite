/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Арифметика групи точок еліптичної кривої над двійковим полем GF(2^m):
 *
 *     y^2 + x*y = x^3 + a*x^2 + b,   a ∈ {0, 1}.
 *
 * Поле задається незвідним поліномом (тричленом або п'ятичленом, масив f
 * ненульових степенів). Внутрішні обчислення ведуться у проєктивних
 * координатах Лопеса-Дахаба (x = X/Z, y = Y/Z^2) — додавання і подвоєння
 * точок без ділення в полі; обернений елемент обчислюється один раз при
 * фінальному переході до афінних координат. Точка на нескінченності
 * подається трійкою (0, 0, 1).
 *
 * Скалярне множення: базове (double-and-add) та оптимізоване з таблицями
 * попередніх обчислень — віконний метод з NAF-розкладанням скаляра або
 * метод гребеня (див. math_ec_precomp_internal.h, opt_level.h).
 *
 * Модуль використовується реалізацією ДСТУ 4145.
 */

#ifndef CRYPTONITE_MATH_EC2M_H
#define CRYPTONITE_MATH_EC2M_H

#include <stdbool.h>

#include "math_ec_point_internal.h"
#include "math_ec_precomp_internal.h"
#include "math_gf2m_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

/** Контекст для работы з группой точек еліптичної кривої. */
typedef struct EC2m_st {
    Gf2mCtx *gf2m;          /* Контекст поля GF(2m). */
    int a;                  /* коефіцієнт еліптичної кривої a (0 або 1). */
    WordArray *b;           /* коефіцієнт еліптичної кривої b. */
    size_t len;             /* Довжина елементів поля у машинних словах. */
} EcGf2mCtx;

/**
 * Створює контекст еліптичної кривої над GF(2^m).
 *
 * @param f ненульові степені незвідного полінома поля
 * @param f_len кількість елементів f (3 — тричлен, 5 — п'ятичлен)
 * @param a коефіцієнт a еліптичної кривої (0 або 1)
 * @param b коефіцієнт b еліптичної кривої
 * @return контекст еліптичної кривої або NULL у разі помилки
 */
EcGf2mCtx *ec2m_alloc(const int *f, size_t f_len, int a, const WordArray *b);

/**
 * Ініціалізує контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @param f не нулевые степени полинома
 * @param f_len розмір f
 * @param a коефіцієнт a еліптичної кривої
 * @param b коефіцієнт b еліптичної кривої
 */
void ec2m_init(EcGf2mCtx *ctx, const int *f, size_t f_len, int a, const WordArray *b);

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
bool ec2m_is_on_curve(const EcGf2mCtx *ctx, const WordArray *px, const WordArray *py);

/**
 * Умножает точку еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k целое число
 * @param r результат скалярного умножения (k * P)
 */
void ec2m_mul(EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k, ECPoint *r);

/**
 * Обчислює суму двох скалярних множень r = m * P + n * Q за таблицями
 * попередніх обчислень (віконний метод з NAF-розкладанням скаляра
 * або метод гребеня).
 *
 * @param ctx контекст еліптичної кривої
 * @param p_precomp попередні обчислення для точки P
 * @param m число, на яке множиться P
 * @param q_precomp попередні обчислення для точки Q або NULL
 * @param n число, на яке множиться Q, або NULL
 * @param r = m * P + n * Q
 *
 * @return код помилки
 */
int ec2m_dual_mul_opt(const EcGf2mCtx *ctx, const EcPrecomp *p_precomp, const WordArray *m,
        const EcPrecomp *q_precomp, const WordArray *n, ECPoint *r);

/**
 * Вычисляет сумму двух умножений точек еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої
 * @param k число на яке умножается P
 * @param q точка еліптичної кривої
 * @param n число на яке умножается Q
 * @param r сумма двух умножений точек еліптичної кривої на число (k * P + n * Q)
 */
void ec2m_dual_mul(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *k,
        const ECPoint *q, const WordArray *n, ECPoint *r);

/**
 * Вычисляет сумму двух умножений точек еліптичної кривої на число.
 *
 * @param ctx контекст еліптичної кривої
 * @param precomp_p предварительные обчислення для точки P
 * @param k число на яке умножается P
 * @param precomp_q предварительные обчислення для точки Q
 * @param n число на яке умножается Q
 * @param r сумма двух умножений точек еліптичної кривої на число (k * P + n * Q)
 */
void ec2m_dual_mul_by_precomp(EcGf2mCtx *ctx, const EcPrecomp *precomp_p, const WordArray *k,
        const EcPrecomp *precomp_q, const WordArray *n, ECPoint *r);

/**
 * Переводить точку з проєктивних координат в афінні:
 * x = X/Z, y = Y/Z^2, Z = 1.
 *
 * @param ctx контекст еліптичної кривої
 * @param p точка еліптичної кривої (модифікується на місці)
 */
void ec2m_point_to_affine(const EcGf2mCtx *ctx, ECPoint *p);

/**
 * Створює копію контексту еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 * @return копія контексту
 */
EcGf2mCtx *ec2m_copy_with_alloc(EcGf2mCtx *ctx);

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
int ec2m_calc_win_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Рассчитывает предобчислення для метода гребня.
 *
 * @param ctx контекст еліптичної кривої
 * @param px x-координата точка еліптичної кривої
 * @param py y-координата точка еліптичної кривої
 * @param w ширина окна
 * @param precomp_p попередні обчислення
 *
 * @return код помилки
 */
int ec2m_calc_comb_precomp(EcGf2mCtx *ctx, const ECPoint *p, int width, EcPrecomp **precomp1);

/**
 * Звільняє контекст еліптичної кривої.
 *
 * @param ctx контекст еліптичної кривої
 */
void ec2m_free(EcGf2mCtx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
