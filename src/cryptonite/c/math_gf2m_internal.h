/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_GF2M_H
#define CRYPTONITE_MATH_GF2M_H

#include <stdbool.h>
#include "word_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct Gf2mCtx_st {
    int *f;
    WordArray *f_ext;
    size_t len;
} Gf2mCtx;

Gf2mCtx *gf2m_alloc(const int *f, size_t f_len);

/**
 * Виконує сложение у поле GF(2^m).
 * out = a + b
 *
 * @param a первое слагаемое
 * @param b второе слагаемое
 * @param out буфер для результата
 */
void gf2m_mod_add(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Виконує возведение у квадрат у поле GF(2^m).
 * out = (a * a) mod p
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для a^2
 */
void gf2m_mod_sqr(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує умножение у поле GF(2^m).
 * out = (a * b) mod p
 *
 * @param ctx Параметри GF(2^m)
 * @param a первый множитель
 * @param b второй множитель
 * @param out буфер для произведения
 */
void gf2m_mod_mul(const Gf2mCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Вычисляет зворотній елемент у поле GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для обратного елементавідa
 */
void gf2m_mod_inv(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Виконує поиск наибольшйого общйого делителя двух многочленов.
 *
 * @param a многочлен
 * @param b многочлен
 * @param gcd буфер для наибольшйого общйого делителя або NULL
 * @param ka буфер для множителя при g або NULL
 * @param kb буфер для множителя при h або NULL
 */
void gf2m_mod_gcd(const WordArray *a, const WordArray *b, WordArray *gcd, WordArray *ka, WordArray *kb);

/**
 * Вычисляет след елемента у поле GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 *
 * @return след елемента
 */
int gf2m_mod_trace(const Gf2mCtx *ctx, const WordArray *a);

/**
 * Находит корень квадратного уравнения x^2 + x = a у поле GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a свободный член
 * @param out буфер для корня розміра n
 *
 * @return true - уравнение имеет решение, <br>
 *         false - уравнение не имеет решения.
 */
bool gf2m_mod_solve_quad(const Gf2mCtx *ctx, const WordArray *a, WordArray *out);

/**
 * Находит квадратный корень елемента у поле GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 * @param a елемент поля
 * @param out буфер для квадратного корня розміра n
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
 * Очищает контекст параметрів GF(2^m).
 *
 * @param ctx Параметри GF(2^m)
 */
void gf2m_free(Gf2mCtx *ctx);


#ifdef  __cplusplus
}
#endif

#endif
