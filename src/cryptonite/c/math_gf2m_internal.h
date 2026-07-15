/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/**
 * Внутрішній модуль арифметики двійкового скінченного поля GF(2^m)
 * (використовується реалізацією ДСТУ 4145 — еліптичні криві над GF(2^m)).
 *
 * Елементи поля представлені у поліноміальному базисі: многочлен над GF(2)
 * степеня < m, коефіцієнти якого зберігаються бітами WordArray
 * (little-endian масив машинних слів word_t, див. word_internal.h).
 * Редукція виконується за незвідним розрідженим многочленом — тричленом
 * x^m + x^k + 1 або п'ятичленом x^m + x^k + x^j + x^l + 1, степені якого
 * задаються масивом f контексту Gf2mCtx.
 * Надаються операції: додавання (XOR), множення, квадрат, обернений елемент,
 * НСД многочленів, слід, розв'язання x^2 + x = a, квадратний корінь.
 */

#ifndef CRYPTONITE_MATH_GF2M_H
#define CRYPTONITE_MATH_GF2M_H

#include <stdbool.h>
#include "word_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

/** Контекст двійкового скінченного поля GF(2^m). */
typedef struct Gf2mCtx_st {
    int *f;            /**< степені ненульових членів редукційного многочлена за спаданням
                            із завершальним нулем: {m, k, 0} — тричлен, {m, k, j, l, 0} — п'ятичлен */
    WordArray *f_ext;  /**< редукційний многочлен у бітовому представленні WordArray */
    size_t len;        /**< довжина елемента поля у словах */
} Gf2mCtx;

/**
 * Створює контекст поля GF(2^m).
 *
 * @param f масив степенів ненульових членів незвідного многочлена за спаданням
 *          із завершальним нулем: {m, k, 0} для тричлена x^m + x^k + 1 або
 *          {m, k, j, l, 0} для п'ятичлена x^m + x^k + x^j + x^l + 1
 * @param f_len кількість елементів масиву f
 * @return контекст GF(2^m) або NULL у разі помилки
 */
Gf2mCtx *gf2m_alloc(const int *f, size_t f_len);

/**
 * Виконує додавання у полі GF(2^m) — побітовий XOR коефіцієнтів.
 * out = a + b
 *
 * @param a перший доданок
 * @param b другий доданок
 * @param out буфер для результату (довжина як в a)
 */
void gf2m_mod_add(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Виконує піднесення до квадрата у полі GF(2^m).
 * out = (a * a) mod f
 *
 * @param ctx параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для a^2 (довжина ctx->len)
 */
void gf2m_mod_sqr(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує множення у полі GF(2^m).
 * out = (a * b) mod f
 *
 * @param ctx параметри GF(2^m)
 * @param a перший множник
 * @param b другий множник
 * @param out буфер для добутку (довжина ctx->len)
 */
void gf2m_mod_mul(const Gf2mCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Обчислює обернений елемент у полі GF(2^m).
 * out = a^(-1) mod f
 *
 * @param ctx параметри GF(2^m)
 * @param a елемент поля, a != 0
 * @param out буфер для оберненого елемента (довжина ctx->len)
 */
void gf2m_mod_inv(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Знаходить найбільший спільний дільник двох многочленів над GF(2)
 * та супутні множники: ka * a = gcd (mod b).
 *
 * @param a многочлен
 * @param b многочлен
 * @param gcd буфер для найбільшого спільного дільника або NULL
 * @param ka буфер для множника при a або NULL
 * @param kb буфер для множника при b або NULL
 */
void gf2m_mod_gcd(const WordArray *a, const WordArray *b, WordArray *gcd, WordArray *ka, WordArray *kb);

/**
 * Обчислює слід елемента у полі GF(2^m):
 * Tr(a) = a + a^2 + a^4 + ... + a^(2^(m-1)).
 *
 * @param ctx параметри GF(2^m)
 * @param a елемент поля
 *
 * @return слід елемента (0 або 1)
 */
int gf2m_mod_trace(const Gf2mCtx *ctx, const WordArray *a);

/**
 * Знаходить корінь квадратного рівняння x^2 + x = a у полі GF(2^m).
 * Розв'язок існує тоді й лише тоді, коли Tr(a) = 0.
 *
 * @param ctx параметри GF(2^m)
 * @param a вільний член
 * @param out буфер для кореня розміру n
 *
 * @return true - рівняння має розв'язок, <br>
 *         false - рівняння не має розв'язку.
 */
bool gf2m_mod_solve_quad(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Знаходить квадратний корінь елемента у полі GF(2^m):
 * out = a^(2^(m-1)), out^2 = a.
 *
 * @param ctx параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для квадратного кореня розміру n
 */
void gf2m_mod_sqrt(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Створює копію контексту параметрів GF(2^m).
 *
 * @param ctx параметри GF(2^m)
 * @return копія контексту
 */
Gf2mCtx *gf2m_copy_with_alloc(const Gf2mCtx *ctx);

/**
 * Звільняє контекст параметрів GF(2^m).
 *
 * @param ctx параметри GF(2^m)
 */
void gf2m_free(Gf2mCtx *ctx);


#ifdef  __cplusplus
}
#endif

#endif
