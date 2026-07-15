/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Внутрішні утиліти конвертації байтових масивів у масиви 32/64-бітних слів
 * і навпаки. Байтові масиви трактуються як little-endian представлення даних
 * незалежно від порядку байтів платформи: на big-endian хостах після
 * копіювання виконується перестановка байтів у межах кожного слова.
 * Додатково: розворот порядку байтів (uint8_swap*) та гарантоване затирання
 * пам'яті (secure_zero).
 */

#include <stddef.h>
#include <string.h>

#include "byte_utils_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/byte_utils_internal.c"

/* Визначення порядку байтів хоста під час виконання:
 * якщо молодший байт одиниці лежить не першим — платформа big-endian. */
const int big_endian_test = 1;
#define is_bigendian() ((*(char*)&big_endian_test) == 0)

/* Розвертає порядок байтів у кожному 8-байтному слові буфера
 * (size — довжина у байтах, кратна 8; in може збігатися з out). */
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

/* Розвертає порядок байтів у кожному 4-байтному слові буфера
 * (size — довжина у байтах, кратна 4; in може збігатися з out). */
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

/* Пакує little-endian байти у масив uint32; хвіст out зануляється.
 * Вимога: out_len * 4 >= in_len. */
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

/* Розпаковує масив uint32 у little-endian байти; хвіст out зануляється.
 * Вимога: out_len >= in_len * 4. */
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

/* Пакує little-endian байти у масив uint64; хвіст out зануляється.
 * Вимога: out_len * 8 >= in_len. */
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

/* Розпаковує масив uint64 у little-endian байти; хвіст out зануляється.
 * Вимога: out_len >= in_len * 8. */
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

/* Перепаковує масив uint32 у масив uint64 зі збереженням little-endian
 * семантики (на big-endian хості 32-бітні половини кожного 64-бітного слова
 * міняються місцями). Вимога: out_len * 8 == in_len * 4. */
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

/* Перепаковує масив uint64 у масив uint32 (обернене до uint32_to_uint64).
 * Вимога: out_len * 4 == in_len * 8. */
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

/* Повертає новий буфер з байтами in у зворотному порядку
 * (конвертація little-endian <-> big-endian). */
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

/* Записує в out байти in у зворотному порядку; підтримує роботу на місці
 * (in == out). Вимога: out_len == in_len. */
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

/* Гарантоване затирання пам'яті: запис через volatile-вказівник
 * не дозволяє компілятору вилучити очищення як "мертвий" код
 * (для секретних даних перед звільненням пам'яті). */
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
