/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
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

#define WORD_LO(_a) ((_a) & HALF_WORD_MASK)
#define WORD_HI(_a) ((_a) >> HALF_WORD_BIT_LENGTH)
#define WA_LEN(_bytes) ((int)(((_bytes) + sizeof(word_t) - 1) >> WORD_BYTE_LEN_SHIFT))
#define WA_LEN_FROM_BITS(_bits) (((_bits) + WORD_BIT_LENGTH - 1) >> WORD_BIT_LEN_SHIFT)

#define WORD_BYTE_LENGTH (sizeof(word_t))

/* Необходимо использовать, якщо не гарантировано, что величина смещения меньше бітовой длины слова. */
#define WORD_LSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) << (_bit)))
#define WORD_RSHIFT(_word, _bit) (((_bit) >= WORD_BIT_LENGTH) ? 0 : ((_word) >> (_bit)))

typedef struct WordArray_st {
    word_t *buf;
    size_t len;
} WordArray;

WordArray *wa_alloc(size_t len);
WordArray *wa_alloc_with_zero(size_t len);
WordArray *wa_alloc_with_one(size_t len);
void wa_zero(WordArray *wa);
void wa_one(WordArray *wa);
WordArray *wa_alloc_from_ba(const ByteArray *in);
WordArray *wa_alloc_from_le(const uint8_t *in, size_t in_len);
WordArray *wa_alloc_from_be(const uint8_t *in, size_t in_len);
int wa_from_ba(const ByteArray *ba, WordArray *wa);
WordArray *wa_copy_with_alloc(const WordArray *in);
int wa_copy(const WordArray *in, WordArray *out);
int wa_copy_part(const WordArray *in, size_t off, size_t len, WordArray *out);
ByteArray *wa_to_ba(const WordArray *wa);
void wa_change_len(WordArray *wa, size_t len);
void wa_free(WordArray *in);
void wa_free_private(WordArray *in);
int word_bit_len(word_t a);
word_t generate_bits(size_t bits);
WordArray *wa_alloc_from_uint8(const uint8_t *in, size_t in_len);
int wa_to_uint8(WordArray *wa, uint8_t *in, size_t in_len);
int wa_from_uint8(WordArray *wa, uint8_t *in, size_t in_len);

int wa_cmp(const WordArray *a, const WordArray *b);

#ifdef  __cplusplus
}
#endif

#endif
