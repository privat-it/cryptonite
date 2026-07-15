/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/**
 * Внутрішній модуль арифметики простого скінченного поля GF(p).
 *
 * Елементи поля — невід'ємні цілі числа, менші за модуль p, у представленні
 * WordArray (little-endian масив машинних слів word_t, див. word_internal.h).
 * Редукція виконується загальним діленням з остачею, без спеціальної форми
 * модуля. Надаються операції: додавання, віднімання, множення, квадрат,
 * піднесення до степеня, обернений елемент, квадратний корінь.
 * Використовується реалізаціями ECDSA та ГОСТ 34.310 (криві над GF(p)).
 */

#ifndef CRYPTONITE_MATH_GFP_H
#define CRYPTONITE_MATH_GFP_H

#include <stdbool.h>

#include "word_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

/** Контекст простого скінченного поля GF(p). */
typedef struct GfpCtx_st {
    WordArray *p;            /**< модуль поля (просте число) */
    WordArray *one;          /**< константа 1 довжини p */
    WordArray *two;          /**< константа 2 довжини p */
    WordArray *invert_const; /**< (2^(n*w))^(-1) mod p, n — довжина p у словах, w — біт у слові;
                                  поправковий множник для gfp_mod_inv */
} GfpCtx;

/**
 * Створює контекст поля GF(p).
 *
 * @param p модуль поля
 * @return контекст GF(p) або NULL у разі помилки
 */
GfpCtx *gfp_alloc(const WordArray *p);

/**
 * Створює копію контексту поля GF(p).
 *
 * @param ctx контекст GF(p)
 * @return копія контексту або NULL у разі помилки
 */
GfpCtx *gfp_copy_with_alloc(const GfpCtx *ctx);

/**
 * Ініціалізує вже виділений контекст поля GF(p): зберігає модуль,
 * константи 1 і 2 та обчислює поправковий множник invert_const.
 *
 * @param ctx контекст GF(p)
 * @param p модуль поля
 */
void gfp_init(GfpCtx *ctx, const WordArray *p);

/**
 * Виконує додавання у полі GF(p).
 * out = (a + b) mod p
 *
 * @param ctx контекст GF(p)
 * @param a перший доданок, a < p
 * @param b другий доданок, b < p
 * @param out буфер для суми (довжина як в a)
 */
void gfp_mod_add(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Виконує віднімання у полі GF(p).
 * out = (a - b) mod p
 *
 * @param ctx контекст GF(p)
 * @param a зменшуване, a < p
 * @param b від'ємник, b < p
 * @param out буфер для різниці (довжина як в a)
 */
void gfp_mod_sub(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Зводить ціле число за модулем p.
 * out = a mod p
 *
 * @param ctx контекст GF(p)
 * @param a число подвійної довжини p (типово — результат множення)
 * @param out буфер для остачі довжини p
 */
void gfp_mod(const GfpCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує множення у полі GF(p).
 * out = (a * b) mod p
 *
 * @param ctx контекст GF(p)
 * @param a перший множник
 * @param b другий множник
 * @param out буфер для добутку (довжина як в a)
 */
void gfp_mod_mul(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Виконує піднесення до квадрата у полі GF(p).
 * out = a^2 mod p
 *
 * @param ctx контекст GF(p)
 * @param a елемент поля
 * @param out буфер для квадрата (довжина як в a)
 */
void gfp_mod_sqr(const GfpCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Обчислює обернений елемент у полі GF(p).
 *
 * @param ctx контекст GF(p)
 * @param a елемент поля, a != 0
 * @return новий масив зі значенням a^(-1) mod p або NULL у разі помилки
 */
WordArray *gfp_mod_inv(const GfpCtx *ctx, const WordArray *a);

/**
 * Виконує піднесення до степеня у полі GF(p).
 * out = a^x mod p
 *
 * @param ctx контекст GF(p)
 * @param a основа
 * @param x показник степеня
 * @param out буфер для результату (довжина як в a)
 */
void gfp_mod_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x, WordArray *out);

/**
 * Обчислює добуток двох степенів у полі GF(p) спільним циклом.
 * out = a^x * b^y mod p
 *
 * @param ctx контекст GF(p)
 * @param a перша основа
 * @param x показник степеня для a
 * @param b друга основа
 * @param y показник степеня для b
 * @param out буфер для результату (довжина як в a)
 */
void gfp_mod_dual_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x,
        const WordArray *b, const WordArray *y, WordArray *out);

/**
 * Обчислює один із квадратних коренів елемента поля GF(p).
 *
 * @param ctx контекст GF(p)
 * @param a елемент поля
 * @param out буфер для a^(1/2) (mod p)
 *
 * @return true — корінь існує (a — квадратичний лишок) і записаний в out,
 *         false — кореня не існує
 */
bool gfp_mod_sqrt(const GfpCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Звільняє контекст поля GF(p).
 *
 * @param ctx контекст GF(p)
 */
void gfp_free(GfpCtx *ctx);

/**
 * Обчислює обернений елемент за модулем p без контексту поля.
 *
 * @param in елемент, in != 0
 * @param p модуль, p != 0
 * @return новий масив зі значенням in^(-1) mod p або NULL,
 *         якщо оберненого не існує чи сталася помилка
 */
WordArray *gfp_mod_inv_core(const WordArray *in, const WordArray *p);

#ifdef  __cplusplus
}
#endif

#endif
