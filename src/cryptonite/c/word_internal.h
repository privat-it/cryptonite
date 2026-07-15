/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/**
 * Внутрішній модуль базового представлення великих цілих чисел.
 *
 * WordArray — беззнакове велике ціле число у вигляді масиву машинних слів
 * word_t (uint64_t на 64-бітних платформах, uint32_t на 32-бітних):
 *  - buf[0] містить наймолодше слово, buf[len - 1] — найстарше
 *    (little-endian порядок слів);
 *  - len — кількість слів у buf; фіксується при виділенні, старші слова
 *    можуть бути нульовими (ведучі нулі допускаються);
 *  - знак не зберігається: всі числа невід'ємні, перенос/займ арифметичних
 *    операцій повертається окремим значенням.
 *
 * Конвертація з/до ByteArray виконується у little-endian порядку байтів.
 */

#ifndef CRYPTONITE_WORD_INTERNAL_H
#define CRYPTONITE_WORD_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "byte_array_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

#if defined(__LP64__) || defined(_WIN64)
# define ARCH64
#else
# define ARCH32
#endif

#ifdef ARCH64
# define WORD_BIT_LENGTH  64
# define DWORD_BIT_LENGTH 128
# define WORD_BIT_LEN_MASK 0x3f
# define WORD_BIT_LEN_SHIFT 6
# define WORD_BYTE_LEN_SHIFT 3
# define HALF_WORD_BIT_LENGTH 32

typedef uint64_t word_t;

# define HALF_WORD_MASK ((word_t)0xffffffff)

#else
# undef ARCH32
# define ARCH32
# define WORD_BIT_LENGTH      32
# define DWORD_BIT_LENGTH     64
# define WORD_BIT_LEN_MASK  0x1f
# define WORD_BIT_LEN_SHIFT    5
# define WORD_BYTE_LEN_SHIFT   2
# define HALF_WORD_BIT_LENGTH 16

typedef uint32_t word_t;

# define HALF_WORD_MASK ((word_t)0xffff)

#endif

/* Молодша та старша половини машинного слова. */
#define WORD_LO(_a) ((_a) & HALF_WORD_MASK)
#define WORD_HI(_a) ((_a) >> HALF_WORD_BIT_LENGTH)
/* Кількість слів, потрібна для зберігання заданої кількості байтів/бітів (округлення вгору). */
#define WA_LEN(_bytes) ((int)(((_bytes) + sizeof(word_t) - 1) >> WORD_BYTE_LEN_SHIFT))
#define WA_LEN_FROM_BITS(_bits) (((_bits) + WORD_BIT_LENGTH - 1) >> WORD_BIT_LEN_SHIFT)

#define WORD_BYTE_LENGTH (sizeof(word_t))

/* Безпечний зсув слова: використовувати, якщо не гарантовано, що величина зсуву
 * менша за бітову довжину слова (зсув на >= WORD_BIT_LENGTH дає 0, а не UB). */
#define WORD_LSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) << (_bit)))
#define WORD_RSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) >> (_bit)))

/** Велике беззнакове ціле число: масив слів buf довжиною len (buf[0] — наймолодше слово). */
typedef struct WordArray_st {
    word_t *buf;
    size_t len;
} WordArray;

/**
 * Створює WordArray заданої довжини (вміст буфера не ініціалізується).
 *
 * @param len кількість слів, len != 0
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc(size_t len);

/**
 * Створює WordArray заданої довжини, заповнений нулями.
 *
 * @param len кількість слів, len != 0
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc_with_zero(size_t len);

/**
 * Створює WordArray заданої довжини зі значенням 1.
 *
 * @param len кількість слів, len != 0
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc_with_one(size_t len);

/**
 * Заповнює число нулями (встановлює значення 0).
 *
 * @param wa велике ціле число або NULL
 */
void wa_zero(WordArray *wa);

/**
 * Встановлює значення 1.
 *
 * @param wa велике ціле число або NULL
 */
void wa_one(WordArray *wa);

/**
 * Створює WordArray за ByteArray; байти інтерпретуються як число у little-endian порядку.
 *
 * @param in масив байтів
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc_from_ba(const ByteArray *in);

/**
 * Створює WordArray за масивом байтів у little-endian порядку.
 *
 * @param in масив байтів
 * @param in_len довжина in у байтах, in_len != 0
 * @return WordArray довжиною ceil(in_len / sizeof(word_t)) слів або NULL у разі помилки
 */
WordArray *wa_alloc_from_le(const uint8_t *in, size_t in_len);

/**
 * Створює WordArray за масивом байтів у big-endian порядку.
 *
 * @param in масив байтів
 * @param in_len довжина in у байтах, in_len != 0
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc_from_be(const uint8_t *in, size_t in_len);

/**
 * Записує вміст ByteArray у наявний WordArray (буфер wa перевиділяється під нову довжину).
 *
 * @param ba масив байтів (little-endian представлення числа)
 * @param wa велике ціле число, ініціалізоване раніше
 * @return код помилки
 */
int wa_from_ba(const ByteArray *ba, WordArray *wa);

/**
 * Створює копію великого цілого числа.
 *
 * @param in велике ціле число
 * @return копія числа або NULL у разі помилки
 */
WordArray *wa_copy_with_alloc(const WordArray *in);

/**
 * Копіює число у наявний буфер; старші слова out доповнюються нулями.
 *
 * @param in велике ціле число
 * @param out буфер-приймач, out->len >= in->len
 * @return код помилки
 */
int wa_copy(const WordArray *in, WordArray *out);

/**
 * Копіює частину числа: len слів починаючи зі зсуву off.
 *
 * @param in велике ціле число, in->len >= off + len
 * @param off зсув у словах
 * @param len кількість слів, out->len == len
 * @param out буфер-приймач (in != out)
 * @return код помилки
 */
int wa_copy_part(const WordArray *in, size_t off, size_t len, WordArray *out);

/**
 * Конвертує WordArray у ByteArray (little-endian порядок байтів).
 *
 * @param wa велике ціле число
 * @return масив байтів або NULL у разі помилки
 */
ByteArray *wa_to_ba(const WordArray *wa);

/**
 * Змінює довжину числа у словах (перевиділяє буфер);
 * при розширенні нові старші слова зануляються.
 *
 * @param wa велике ціле число
 * @param len нова довжина у словах
 */
void wa_change_len(WordArray *wa, size_t len);

/**
 * Звільняє пам'ять числа.
 *
 * @param in велике ціле число або NULL
 */
void wa_free(WordArray *in);

/**
 * Звільняє пам'ять числа з попереднім гарантованим затиранням буфера
 * (для секретних даних).
 *
 * @param in велике ціле число або NULL
 */
void wa_free_private(WordArray *in);

/**
 * Повертає бітову довжину слова (номер найстаршого ненульового біта).
 *
 * @param a машинне слово
 * @return довжина у бітах: 0 для a == 0, інакше 1..WORD_BIT_LENGTH
 */
int word_bit_len(word_t a);

word_t generate_bits(size_t bits);

/**
 * Створює WordArray за масивом байтів у little-endian порядку.
 *
 * @param in масив байтів
 * @param in_len довжина in у байтах, in_len != 0
 * @return WordArray або NULL у разі помилки
 */
WordArray *wa_alloc_from_uint8(const uint8_t *in, size_t in_len);

/**
 * Записує число у байтовий буфер (little-endian порядок байтів).
 *
 * @param wa велике ціле число
 * @param in буфер-приймач
 * @param in_len довжина буфера у байтах, in_len >= wa->len * sizeof(word_t)
 * @return код помилки
 */
int wa_to_uint8(WordArray *wa, uint8_t *in, size_t in_len);

int wa_from_uint8(WordArray *wa, uint8_t *in, size_t in_len);

/**
 * Порівнює два числа як масиви: спочатку за довжиною, далі побайтово (memcmp).
 * Для числового порівняння значень використовується int_cmp.
 *
 * @param a велике ціле число
 * @param b велике ціле число
 * @return 0 — масиви однакові, інакше ненульове значення
 */
int wa_cmp(const WordArray *a, const WordArray *b);

#ifdef  __cplusplus
}
#endif

#endif
