/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_BYTE_UTILS_H
#define CRYPTONITE_BYTE_UTILS_H

#include <inttypes.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define UINT32_LEN             4
#define UINT64_LEN             8

int uint8_to_uint32(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len);
int uint32_to_uint8(const uint32_t *in, size_t in_len, uint8_t *out, size_t out_len);
int uint64_to_uint8(const uint64_t *in, size_t in_len, uint8_t *out, size_t out_len);
int uint8_to_uint64(const uint8_t *in, size_t in_len, uint64_t *out, size_t out_len);
int uint32_to_uint64(const uint32_t *in, size_t in_len, uint64_t *out, size_t out_len);
int uint64_to_uint32(const uint64_t *in, size_t in_len, uint32_t *out, size_t out_len);
uint8_t *uint8_swap_with_alloc(const uint8_t *in, size_t in_len);
int uint8_swap(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
void secure_zero(void *s, size_t n);

#ifdef  __cplusplus
}
#endif

#endif
