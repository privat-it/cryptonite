/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/**
 * Внутрішня частина ByteArray: визначення структури (buf — вказівник на дані,
 * len — довжина у байтах) та службові функції конвертації у масиви
 * 32/64-бітних слів і назад.
 *
 * Числові функції цього модуля (ba_trim_leading_zeros, ba_truncate,
 * ba_is_zero) трактують вміст buf як число у little-endian порядку байтів:
 * buf[0] — наймолодший байт, старші (ведучі) нулі — у кінці масиву.
 */

#ifndef CRYPTONITE_BYTE_ARRAY_INTERNAL_H
#define CRYPTONITE_BYTE_ARRAY_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/** Масив байтів: buf — дані, len — довжина у байтах. */
struct ByteArray_st {
    uint8_t *buf;
    size_t len;
};

/**
 * Создаёт контекст массива байт.
 *
 * @param buf массив байт с инвертированным порядком байт
 * @param buf_len размер массива байт
 * @return контекст массива байт
 */
ByteArray *ba_alloc_from_uint8_be(const uint8_t *buf, size_t buf_len);

/**
 * Создаёт контекст массива байт по массиву 64-битных слов.
 *
 * @param buf массив 64 битных слов
 * @param buf_len количество слов в buf
 * @return контекст массива байт
 */
ByteArray *ba_alloc_from_uint64(const uint64_t *buf, size_t buf_len);

/**
 * Возвращает данные, которые хранит контекст массива байт, в формате массива 64-битных слов.
 * Выделяет память.
 *
 * @param ba контекст массива байт
 * @param buf массив 64-битных слов
 * @param buf_len количество слов buf
 * @return код ошибки
 */
int ba_to_uint64_with_alloc(const ByteArray *ba, uint64_t **buf, size_t *buf_len);

/**
 * Возвращает данные, которые хранит контекст массива байт, в формате массива 32-битных слов.
 * Не выделяет память.
 *
 * @param ba контекст массива байт
 * @param buf массив 32-битных слов
 * @param buf_len количество слов buf
 * @return код ошибки
 */
int ba_to_uint32(const ByteArray *ba, uint32_t *buf, size_t buf_len);

/**
 * Записує масив 32-бітних слів у наявний контекст масиву байтів
 * (буфер перевиділяється під нову довжину).
 *
 * @param buf масив 32-бітних слів
 * @param buf_len кількість слів у buf
 * @param ba контекст масиву байтів
 * @return код помилки
 */
int ba_from_uint32(const uint32_t *buf, size_t buf_len, ByteArray *ba);

/**
 * Створює контекст масиву байтів за масивом 32-бітних слів.
 *
 * @param buf масив 32-бітних слів
 * @param buf_len кількість слів у buf
 * @return контекст масиву байтів або NULL у разі помилки
 */
ByteArray *ba_alloc_from_uint32(const uint32_t *buf, size_t buf_len);

/**
 * Повертає дані контексту масиву байтів у форматі масиву 64-бітних слів.
 * Не виділяє пам'ять.
 *
 * @param ba контекст масиву байтів
 * @param buf буфер для 64-бітних слів
 * @param buf_len кількість слів buf, buf_len == ceil(ba->len / 8)
 * @return код помилки
 */
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);

/**
 * Записує масив 64-бітних слів у наявний контекст масиву байтів
 * (буфер перевиділяється під нову довжину).
 *
 * @param buf масив 64-бітних слів
 * @param buf_len кількість слів у buf
 * @param ba контекст масиву байтів
 * @return код помилки
 */
int ba_from_uint64(const uint64_t *buf, size_t buf_len, ByteArray *ba);
int ba_to_uint64(const ByteArray *ba, uint64_t *buf, size_t buf_len);

/**
 * Відкидає старші (ведучі) нульові байти числа — нулі у кінці буфера
 * (little-endian); буфер перевиділяється до фактичної довжини.
 *
 * @param ba контекст масиву байтів
 * @return код помилки
 */
int ba_trim_leading_zeros(ByteArray *ba);

/**
 * Усікає число до заданої кількості бітів: обнуляє всі біти,
 * старші за bit_len (little-endian представлення).
 *
 * @param a контекст масиву байтів
 * @param bit_len кількість бітів, що залишаються
 * @return код помилки
 */
int ba_truncate(ByteArray *a, size_t bit_len);

/**
 * Перевіряє, чи всі байти масиву нульові.
 *
 * @param a контекст масиву байтів або NULL
 * @return true — масив нульовий або a == NULL, false — інакше
 */
bool ba_is_zero(const ByteArray *a);

#ifdef  __cplusplus
}
#endif

#endif
