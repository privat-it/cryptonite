/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_INT_H
#define CRYPTONITE_MATH_INT_H

#include <stdbool.h>

#include "word_internal.h"
#include "prng.h"

#define WORD_MASK (word_t)(-1)
#define MAX_WORD (dword_t)((dword_t)WORD_MASK + 1)

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dword_st {
    word_t lo;
    word_t hi;
} Dword;

/**
 * Перевіряє равенство нулю большого целого числа.
 *
 * @param a велике целое число
 *
 * @return true - число равно нулю, false - число неравно нулю
 */
bool int_is_zero(const WordArray *a);

/**
 * Перевіряє равенство единице большого целого числа.
 *
 * @param a велике целое число
 *
 * @return true - число равно единице, false - число неравно единице
 */
bool int_is_one(const WordArray *a);

/**
 * Перевіряє равенство двух больших целых чисел.
 *
 * @param a велике целое число
 * @param b велике целое число
 *
 * @return true - числа равны, false - числа не равны
 */
bool int_equals(const WordArray *a, const WordArray *b);

/**
 * Сравнивает два больших целых числа.
 *
 * @param a велике целое число
 * @param b велике целое число
 *
 * @return 0 - якщо a = b, -1 - якщо a < b, 1 - якщо a > b
 */
int int_cmp(const WordArray *a, const WordArray *b);

/**
 * Вычисляет сумму двух больших целых чисел.
 * out = a + b.
 *
 * @param a велике целое число длиной n
 * @param b велике целое число длиной n
 * @param out буфер для суммы двух больших целых чисел длиной n
 *
 * @return перенос после сложения: 0 або 1
 */
word_t int_add(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Вычисляет разность двух больших целых чисел.
 * out = a - b.
 *
 * @param a велике целое число длиной n
 * @param b велике целое число длиной n
 * @param out буфер для разности двух больших целых чисел длиной n
 *
 * @return займ после вычитания: 0 або -1
 */
int int_sub(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * повертає довжину большого целого числа у словах без ведущих нулей.
 *
 * @param a велике целое число
 *
 * @return довжина большого целого числа у словах без ведущих нулей
 */
size_t int_word_len(const WordArray *a);

/**
 * повертає довжину у бітах большого целого числа.
 *
 * @param a велике целое число
 *
 * @return довжина большого целого у бітах
 */
size_t int_bit_len(const WordArray *a);

/**
 * Виконує усечение большого целого числа до заданного числа біт.
 *
 * @param a велике целое число
 * @param bit_len число оставляемых біт
 *
 * @return код помилки
 */
void int_truncate(WordArray *a, size_t bit_len);

/**
 * повертає заданный біт большого целого числа.
 *
 * @param a велике целое число
 * @param bit_num номер біта
 *
 * @return заданный біт числа
 */
int int_get_bit(const WordArray *a, size_t bit_num);

/**
 * Сдвигает велике целое на заданное число біт влево.
 *
 * @param a велике целое число
 * @param shift величина сдвига у бітах
 * @param out буфер для результата сдвига
 */
void int_lshift(const WordArray *a, size_t shift, WordArray *out);

/**
 * Сдвигает велике целое на заданное число біт вправо.
 *
 * @param a_hi старшее слововід"a"
 * @param a велике целое число
 * @param shift величина сдвига у бітах
 * @param out буфер для результата сдвига
 */
void int_rshift(word_t a_hi, const WordArray *a, size_t shift, WordArray *out);

/**
 * Вычисляет произведение двух больших целых чисел.
 *
 * @param a первое велике число длиной n
 * @param b второе велике число длиной n
 * @param out буфер для результата произведения длины 2n
 */
void int_mul(const WordArray *a, const WordArray *b, WordArray *out);

/**
 * Вычисляет кводрат большого целого чисела.
 *
 * @param a первое велике число длиной n
 * @param out буфер для результата произведения длины 2n
 */
void int_sqr(const WordArray *a, WordArray *out);

/**
 * Вычисляет частное і остатоквідделения больших целых чисел.
 * a = q * b + r
 *
 * @param a делимое длины 2n
 * @param b делитель длины n
 * @param q буфер для частного длины 2n або NULL
 * @param r буфер для остатка длины n або NULL
 */
void int_div(const WordArray *a, const WordArray *b, WordArray *q, WordArray *r);

/**
 * Вычисляет целую часть квадратного корня.
 * Используется алгоритм Ньютона.
 *
 * @param in большое целое число
 * @param out целую часть квадратного корня от in
 */
void int_sqrt(const WordArray *in, WordArray *out);

int int_rand(PrngCtx *prng, const WordArray *in, WordArray *out);
int int_prand(const WordArray *in, WordArray *out);

int int_is_prime(WordArray *a, bool *is_prime);

int int_rabin_miller_primary_test(WordArray *num, bool *is_prime);

int int_fermat_primary_test(WordArray *num, bool *is_prime);

void factorial(int n, WordArray *fac);

/**
 * Вычисляет a * b / c.
 *
 * Необходимо чтобы b <= c.
 *
 * @param a большое целое длины n
 * @param b целое
 * @param c целое
 * @param n размер a в словах
 * @param abc массив для результата длины n
 *
 * @return код ошибки в случае ошибки выделения памяти
 */
int int_mult_and_div(const WordArray *a, word_t b, word_t c, int n, WordArray *abc);

int int_get_naf(const WordArray *in, int width, int **out);

int int_get_naf_extra_add(const WordArray *in, const int *naf, int width, int *extra_addition);

int int_gen_prime(const size_t bits, PrngCtx *prng, WordArray **out);

#ifdef  __cplusplus
}
#endif

#endif
