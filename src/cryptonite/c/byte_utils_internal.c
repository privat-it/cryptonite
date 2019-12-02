/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stddef.h>
#include <string.h>

#include "byte_utils_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/byte_utils_internal.c"

const int big_endian_test = 1;
#define is_bigendian() ((*(char*)&big_endian_test) == 0)

#define swap_word64(in, out, size)              \
    {                                           \
        uint8_t *_in = (uint8_t *)(in);         \
        uint8_t *_out = (uint8_t *)(out);       \
        uint8_t _tmp[8];                        \
        size_t _i;                              \
                                                \
        for (_i = 0; _i < size; _i += UINT64_LEN) {  \
            _tmp[0] = _in[_i + 7];                   \
            _tmp[1] = _in[_i + 6];                   \
            _tmp[2] = _in[_i + 5];                   \
            _tmp[3] = _in[_i + 4];                   \
            _tmp[4] = _in[_i + 3];                   \
            _tmp[5] = _in[_i + 2];                   \
            _tmp[6] = _in[_i + 1];                   \
            _tmp[7] = _in[_i + 0];                   \
            _out[_i + 0] = _tmp[0];                  \
            _out[_i + 1] = _tmp[1];                  \
            _out[_i + 2] = _tmp[2];                  \
            _out[_i + 3] = _tmp[3];                  \
            _out[_i + 4] = _tmp[4];                  \
            _out[_i + 5] = _tmp[5];                  \
            _out[_i + 6] = _tmp[6];                  \
            _out[_i + 7] = _tmp[7];                  \
        }                                            \
    }

#define swap_word32(in, out, size)              \
    {                                           \
        uint8_t *_in = (uint8_t *)(in);         \
        uint8_t *_out = (uint8_t *)(out);       \
        uint8_t _tmp[4];                        \
        size_t _i;                              \
        size_t _size = (size_t)(size);          \
                                                \
        for (_i = 0; _i < _size; _i += 4) {     \
            _tmp[0] = _in[_i + 3];              \
            _tmp[1] = _in[_i + 2];              \
            _tmp[2] = _in[_i + 1];              \
            _tmp[3] = _in[_i + 0];              \
            _out[_i + 0] = _tmp[0];             \
            _out[_i + 1] = _tmp[1];             \
            _out[_i + 2] = _tmp[2];             \
            _out[_i + 3] = _tmp[3];             \
        }                                       \
    }

int uint8_to_uint32(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len * UINT32_LEN >= in_len);

    memcpy(out, in, in_len);
    if (out_len * UINT32_LEN > in_len) {
        memset((uint8_t *)out + in_len, 0, out_len * UINT32_LEN - in_len);
    }

    if (is_bigendian()) {
        swap_word32(out, out, in_len);
    }

cleanup:

    return ret;
}

int uint32_to_uint8(const uint32_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len >= in_len * UINT32_LEN);

    memcpy(out, in, in_len * UINT32_LEN);
    if (out_len > in_len * UINT32_LEN) {
        memset(out + in_len * UINT32_LEN, 0, out_len - in_len * UINT32_LEN);
    }

    if (is_bigendian()) {
        swap_word32(out, out, in_len * UINT32_LEN);
    }

cleanup:

    return ret;
}

int uint8_to_uint64(const uint8_t *in, size_t in_len, uint64_t *out, size_t out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len * UINT64_LEN >= in_len);

    memcpy(out, in, in_len);
    if (out_len * UINT64_LEN > in_len) {
        memset((uint8_t *)out + in_len, 0, out_len * UINT64_LEN - in_len);
    }

    if (is_bigendian()) {
        swap_word64(out, out, in_len);
    }

cleanup:

    return ret;
}

int uint64_to_uint8(const uint64_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len >= in_len * UINT64_LEN);

    memcpy(out, in, in_len * UINT64_LEN);
    if (out_len > in_len * UINT64_LEN) {
        memset(out + in_len * UINT64_LEN, 0, out_len - in_len * UINT64_LEN);
    }

    if (is_bigendian()) {
        swap_word64(out, out, in_len * UINT64_LEN);
    }

cleanup:

    return ret;
}

int uint32_to_uint64(const uint32_t *in, size_t in_len, uint64_t *out, size_t out_len)
{
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len * UINT64_LEN == in_len * UINT32_LEN);

    if (is_bigendian()) {
        for (i = 0; i < in_len; i += 2) {
            ((uint32_t *)out)[i + 1] = in[i];
            ((uint32_t *)out)[i] = in[i + 1];
        }
    } else {
        memcpy(out, in, in_len * UINT32_LEN);
    }

cleanup:

    return ret;
}

int uint64_to_uint32(const uint64_t *in, size_t in_len, uint32_t *out, size_t out_len)
{
    size_t i;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len * UINT32_LEN == in_len * UINT64_LEN);

    if (is_bigendian()) {
        for (i = 0; i < out_len; i += 2) {
            out[i + 1] = ((uint32_t *)in)[i];
            out[i] = ((uint32_t *)in)[i + 1];
        }
    } else {
        memcpy(out, in, in_len * UINT64_LEN);
    }

cleanup:

    return ret;
}

uint8_t *uint8_swap_with_alloc(const uint8_t *in, size_t in_len)
{
    size_t i;
    int ret = RET_OK;
    uint8_t *out = NULL;

    MALLOC_CHECKED(out, in_len);

    for (i = 0; i < in_len; i++) {
        out[in_len - 1 - i] = in[i];
    }

cleanup:

    return out;
}

int uint8_swap(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    size_t i;
    uint8_t tmp;
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(in_len != 0);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(out_len == in_len);

    if (in == out) {
        for (i = 0; i < out_len / 2; i++) {
            tmp = out[i];
            out[i] = out[out_len - 1 - i];
            out[out_len - 1 - i] = tmp;
        }
    } else {
        for (i = 0; i < out_len; i++) {
            out[out_len - 1 - i] = in[i];
        }
    }

cleanup:

    return ret;
}

void secure_zero(void *s, size_t n)
{
    if (s == NULL) {
        return;
    }

    volatile char *p = s;
    while (n--) {
        *p++ = 0;
    }
}
