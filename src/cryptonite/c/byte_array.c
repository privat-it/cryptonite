/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stddef.h>
#include <string.h>

#include "byte_array.h"
#include "byte_array_internal.h"
#include "byte_utils_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/byte_array.c"

ByteArray *ba_alloc(void)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    MALLOC_CHECKED(ba, sizeof (ByteArray));

    ba->buf = NULL;
    ba->len = 0;

cleanup:

    return ba;
}

ByteArray *ba_alloc_by_len(size_t len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    MALLOC_CHECKED(ba, sizeof (ByteArray));
    MALLOC_CHECKED(ba->buf, len);

    ba->len = len;

    return ba;
cleanup:
    return NULL;
}

ByteArray *ba_alloc_from_uint8(const uint8_t *buf, size_t buf_len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if (buf != NULL) {
        MALLOC_CHECKED(ba, sizeof (ByteArray));
        if (buf_len != 0) {
            MALLOC_CHECKED(ba->buf, buf_len);
            memcpy(ba->buf, buf, buf_len);
        } else {
            ba->buf = NULL;
        }

        ba->len = buf_len;
    }

    return ba;

cleanup:

    free(ba);

    return NULL;
}

int ba_alloc_from_file(const char *path, ByteArray **out)
{
    FILE *p_file = NULL;
    size_t file_size;
    size_t result;
    ByteArray *ba = NULL;
    int ret = RET_OK;

    CHECK_PARAM(path != NULL);
    CHECK_PARAM(out != NULL);

    p_file = fopen(path, "rb");
    if (!p_file) {
        SET_ERROR(RET_FILE_OPEN_ERROR);
    }

    fseek(p_file, 0, SEEK_END);
    file_size = ftell(p_file);
    rewind(p_file);

    if (file_size == (file_size) - 1L) {
        SET_ERROR(RET_FILE_GET_SIZE_ERROR);
    }

    CHECK_NOT_NULL(ba = ba_alloc_by_len(file_size));

    result = fread(ba->buf, 1, file_size, p_file);
    if (result != file_size) {
        SET_ERROR(RET_FILE_READ_ERROR);
    }

    *out = ba;
    ba = NULL;

cleanup:

    if (p_file) {
        fclose(p_file);
    }

    ba_free(ba);

    return ret;
}

static bool is_char_0_f(char ch)
{
    return (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') || (ch >= '0' && ch <= '9');
}

ByteArray *ba_alloc_from_le_hex_string(const char *data)
{
    ByteArray *out_ba = NULL;
    uint8_t *out = NULL;
    char tmp[3] = {0};
    size_t i;
    size_t len;
    int ret = RET_OK;

    CHECK_PARAM(data != NULL);

    len = strlen(data);
    if (len % 2 != 0) {
        SET_ERROR(RET_INVALID_HEX_STRING);
    }

    MALLOC_CHECKED(out, len / 2);

    for (i = 0; i < len / 2; i++) {
        if (!is_char_0_f(data[2 * i]) || !is_char_0_f(data[2 * i + 1])) {
            SET_ERROR(RET_INVALID_HEX_STRING);
        }
        memcpy(tmp, data + 2 * i, 2);
        out[i] = (uint8_t) strtol(tmp, NULL, 16);
    }

    CHECK_NOT_NULL(out_ba = ba_alloc_from_uint8(out, len / 2));

cleanup:

    free(out);

    return out_ba;
}

ByteArray *ba_alloc_from_str(const char *buf)
{
    ByteArray *ans = NULL;
    int ret = RET_OK;

    if (buf != NULL) {
        CHECK_NOT_NULL(ans = ba_alloc_from_uint8((const uint8_t *)buf, strlen(buf)));
    }

cleanup:

    return ans;
}

ByteArray *ba_copy_with_alloc(const ByteArray *in, size_t off, size_t len)
{
    ByteArray *ba = NULL;
    int ret = RET_OK;

    if ((in != NULL) && (in->len >= (off + len))) {
        if (len == 0) {
            len = in->len - off;
        }

        MALLOC_CHECKED(ba, sizeof (ByteArray));
        MALLOC_CHECKED(ba->buf, len);

        memcpy(ba->buf, &in->buf[off], len);
        ba->len = len;
    }

    return ba;
cleanup:

    free(ba);
    return NULL;
}

int ba_swap(const ByteArray *a)
{
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);
    DO(uint8_swap(a->buf, a->len, a->buf, a->len));

cleanup:

    return ret;
}

int ba_xor(const ByteArray *a, const ByteArray *b)
{
    int ret = RET_OK;
    size_t i;

    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(b->len >= a->len);

    for (i = 0; i < a->len; i++) {
        a->buf[i] ^= b->buf[i];
    }

cleanup:

    return ret;
}

int ba_set(ByteArray *a, uint8_t value)
{
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);

    memset(a->buf, value, a->len);

cleanup:

    return ret;
}

ByteArray *ba_join(const ByteArray *a, const ByteArray *b)
{
    ByteArray *out = NULL;
    int ret = RET_OK;

    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);

    CHECK_NOT_NULL(out = ba_alloc_by_len(a->len + b->len));
    memcpy(out->buf, a->buf, a->len);
    memcpy(out->buf + a->len, b->buf, b->len);

cleanup:

    return out;
}

int ba_cmp(const ByteArray *a, const ByteArray *b)
{
    if (a && b) {
        if (a->len != b->len) {
            return (int)(a->len - b->len);
        }

        return memcmp(a->buf, b->buf, a->len);
    }

    ERROR_CREATE(RET_INVALID_PARAM);

    return -1;
}

size_t ba_get_len(const ByteArray *ba)
{
    return (ba != NULL) ? ba->len : 0;
}

const uint8_t *ba_get_buf(const ByteArray *ba)
{
    if (ba) {
        return ba->buf;
    }
    ERROR_CREATE(RET_INVALID_PARAM);

    return NULL;
}

int ba_from_uint8(const uint8_t *buf, size_t buf_len, ByteArray *ba)
{
    int ret = RET_OK;

    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != 0);
    CHECK_PARAM(ba != NULL);

    REALLOC_CHECKED(ba->buf, buf_len, ba->buf);

    memcpy(ba->buf, buf, buf_len);
    ba->len = buf_len;

cleanup:

    return ret;
}

int ba_to_uint8_with_alloc(const ByteArray *ba, uint8_t **buf, size_t *buf_len)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(buf_len != NULL);

    MALLOC_CHECKED(*buf, ba->len);
    memcpy(*buf, ba->buf, ba->len);
    *buf_len = ba->len;

cleanup:

    return ret;
}

int ba_to_uint8(const ByteArray *ba, uint8_t *buf, size_t buf_len)
{
    int ret = RET_OK;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(buf != NULL);
    CHECK_PARAM(ba->len <= buf_len);

    memcpy(buf, ba->buf, ba->len);
cleanup:
    return ret;
}

int ba_to_file(const ByteArray *ba, const char *path)
{
    int ret = RET_OK;
    FILE *pFile = NULL;
    size_t result;

    CHECK_PARAM(ba != NULL);
    CHECK_PARAM(path != NULL);

    pFile = fopen(path, "wb");

    if (!pFile) {
        SET_ERROR(RET_FILE_OPEN_ERROR);
    }

    result = fwrite(ba->buf, sizeof(uint8_t), ba->len, pFile);
    if (result != ba->len) {
        SET_ERROR(RET_FILE_WRITE_ERROR);
    }

cleanup:

    if (pFile) {
        fclose(pFile);
    }

    return ret;
}

int ba_copy(const ByteArray *in, size_t in_off, size_t len, ByteArray *out, size_t out_off)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (len == 0) {
        len = in->len - in_off;
    }
    CHECK_PARAM(in_off + len <= in->len);
    CHECK_PARAM(out_off + len <= out->len);

    memcpy(&out->buf[out_off], &in->buf[in_off], len);
cleanup:
    return ret;
}

int ba_append(const ByteArray *in, size_t in_off, size_t len, ByteArray *out)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

    if (len == 0) {
        len = in->len - in_off;
    }
    CHECK_PARAM(in_off + len <= in->len);
    REALLOC_CHECKED(out->buf, out->len + len, out->buf);
    memcpy(&out->buf[out->len], &in->buf[in_off], len);
    out->len += len;

cleanup:

    return ret;
}

int ba_print(FILE *stream, const ByteArray *ba)
{
    int ret = RET_OK;

    CHECK_PARAM(stream != NULL);

    size_t j = 0;
    uint8_t *u8 = (uint8_t *) ba_get_buf(ba);
    size_t len = ba_get_len(ba);
    for (j = 0; j < len; j++) {
        DO(fprintf(stream, "%02X", u8[j]) > 0 ? RET_OK : RET_FILE_WRITE_ERROR);
        fflush(stream);
    }
    fprintf(stream, "\n");
    fflush(stream);

cleanup:
    return ret;
}

void ba_free(ByteArray *ba)
{
    if (ba) {
        free(ba->buf);
    }
    free(ba);
}


int ba_change_len(ByteArray *ba, size_t len)
{
    int ret = RET_OK;
    if (ba == NULL) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    REALLOC_CHECKED(ba->buf, len, ba->buf);

    if (ba->len < len) {
        memset(&ba->buf[ba->len], 0, len - ba->len);
    }
    ba->len = len;

cleanup:

    return ret;
}

void ba_free_private(ByteArray *ba)
{
    if (ba) {
        secure_zero(ba->buf, ba->len);
        free(ba->buf);
    }
    free(ba);
}
