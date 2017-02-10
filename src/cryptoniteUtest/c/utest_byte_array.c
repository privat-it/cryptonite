/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>

#include "utest.h"
#include "byte_array.h"

static void test_ba_alloc(void)
{
    ByteArray *ba = NULL;
    const char *text = NULL;
    const char *path = "file.txt";
    FILE *f = NULL;
    const uint8_t buf[] = {'a', 'b', 'c'};
    const uint8_t buf_be[] = {'c', 'b', 'a'};
    uint32_t val_u32;
    uint64_t val_u64;

    val_u32 = (uint32_t)0x04030201;
    val_u64 = (uint64_t)0x0807060504030201;

    ASSERT_NOT_NULL(ba = ba_alloc());
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(ba = ba_alloc_by_len(40));
    ASSERT_TRUE(40 == ba_get_len(ba));
    ba_free(ba);
    ba = NULL;

    text = "abc";
    ASSERT_NOT_NULL(ba = ba_alloc_from_str(text));
    ASSERT_TRUE(strlen(text) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), text, strlen(text)));
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint8(buf, sizeof(buf)));
    ASSERT_TRUE(sizeof(buf) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), buf, sizeof(buf)));
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint8_be(buf, sizeof(buf)));
    ASSERT_TRUE(sizeof(buf) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), buf_be, sizeof(buf)));
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint32(&val_u32, 1));
    ASSERT_TRUE(sizeof(val_u32) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), &val_u32, sizeof(val_u32)));
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint64(&val_u64, 1));
    ASSERT_TRUE(sizeof(val_u64) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), &val_u64, sizeof(val_u64)));
    ba_free(ba);
    ba = NULL;

    ASSERT_NOT_NULL(f = fopen(path, "w"));
    ASSERT_TRUE(fprintf(f, "%s", text) == (int)strlen(text));
    ASSERT_TRUE(fclose(f) == 0);
    ASSERT_RET_OK(ba_alloc_from_file(path, &ba));
    ASSERT_TRUE(strlen(text) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), text, strlen(text)));
    ba_free(ba);
    ba = NULL;

cleanup:

    ba_free(ba);
    remove(path);
}

static void test_ba_from_uint8(void)
{
    ByteArray *ba = NULL;
    const uint8_t buf[] = {'a', 'b', 'c'};
    ASSERT_NOT_NULL(ba = ba_alloc());
    ASSERT_RET_OK(ba_from_uint8(buf, sizeof(buf), ba));
    ASSERT_TRUE(sizeof(buf) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), buf, sizeof(buf)));

cleanup:
    ba_free(ba);
}

static void test_ba_from_uint32(void)
{
    ByteArray *ba = NULL;
    const uint32_t val_u32 = (uint32_t)0x04030201;
    ASSERT_NOT_NULL(ba = ba_alloc());
    ASSERT_RET_OK(ba_from_uint32(&val_u32, 1, ba));
    ASSERT_TRUE(sizeof(val_u32) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), &val_u32, sizeof(val_u32)));

cleanup:
    ba_free(ba);
}

static void test_ba_from_uint64(void)
{
    ByteArray *ba = NULL;
    const uint64_t val_u64 = (uint64_t)0x0807060504030201;
    ASSERT_NOT_NULL(ba = ba_alloc());
    ASSERT_RET_OK(ba_from_uint64(&val_u64, 1, ba));
    ASSERT_TRUE(sizeof(val_u64) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), &val_u64, sizeof(val_u64)));

cleanup:
    ba_free(ba);
}

static void test_ba_to_file(void)
{
    ByteArray *ba = NULL;
    const char *text = "abc";
    const char *path = "file.txt";
    FILE *f = NULL;
    char content[3 + 1];

    ASSERT_NOT_NULL(ba = ba_alloc_from_str(text));
    ASSERT_TRUE(strlen(text) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), text, strlen(text)));
    ASSERT_RET_OK(ba_to_file(ba, path));

    ASSERT_NOT_NULL(f = fopen(path, "r"));
    ASSERT_TRUE(fscanf(f, "%s", content) == 1);
    ASSERT_TRUE(fclose(f) == 0);

    ASSERT_TRUE(strlen(content) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), content, strlen(content)));
    ASSERT_TRUE(remove(path) == 0);

cleanup:

    ba_free(ba);
}

static void test_ba_to_file_with_wrong_name(void)
{
    ByteArray *ba = ba_alloc_from_str("abc");
    const char *path = "qweqeqweeq/qweqweqwe.txt";

    ASSERT_TRUE(ba_to_file(ba, path) == RET_FILE_OPEN_ERROR);

    ba_free(ba);
}

static void test_ba_alloc_from_file_with_wrong_name(void)
{
    ByteArray *ba = NULL;
    const char *path = "cdvntmkhgndjyxskcfxt.txt";

    ba_alloc_from_file(path, &ba);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_NOT_NULL(err_ctx);
    ASSERT_TRUE(err_ctx->error_code == RET_FILE_OPEN_ERROR);

cleanup:

    ba_free(ba);
}

static void test_ba_to_with_alloc(void)
{
    ByteArray *ba = NULL;
    uint8_t *u8_buf = NULL;
    uint64_t *u64_buf = NULL;
    size_t u_size;
    uint64_t val_u64;

    val_u64 = (uint64_t)0x0807060504030201;

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint64(&val_u64, 1));
    ASSERT_TRUE(sizeof(val_u64) == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), &val_u64, sizeof(val_u64)));

    ASSERT_RET_OK(ba_to_uint8_with_alloc(ba, &u8_buf, &u_size));
    ASSERT_TRUE(u_size == ba_get_len(ba));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba), u8_buf, u_size));
    free(u8_buf);
    u8_buf = NULL;

    ASSERT_RET_OK(ba_to_uint64_with_alloc(ba, &u64_buf, &u_size));
    ASSERT_TRUE(u_size == (ba_get_len(ba) / sizeof(uint64_t)));
    ASSERT_TRUE(u64_buf[0] == val_u64);

cleanup:

    free(u8_buf);
    free(u64_buf);
    ba_free(ba);
}

static void test_ba_trim_leading_zeros(void)
{
    ByteArray *ba = NULL;
    uint64_t val_u64;
    uint32_t val_32;

    val_u64 = (uint64_t)(0x08070605);

    ASSERT_NOT_NULL(ba = ba_alloc_from_uint64(&val_u64, 1));
    ASSERT_TRUE(ba_get_len(ba) == sizeof(uint64_t));
    ASSERT_RET_OK(ba_trim_leading_zeros(ba));
    ASSERT_TRUE(ba_get_len(ba) == sizeof(uint32_t));
    ASSERT_RET_OK(ba_to_uint32(ba, &val_32, 2));
    ASSERT_TRUE(val_32 == ((uint32_t)0x08070605));

cleanup:
    ba_free(ba);
}

static void test_ba_join(void)
{
    ByteArray *ba12 = NULL;
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    const char *str = "Hello World";

    ASSERT_NOT_NULL(ba1 = ba_alloc_from_str("Hello"));
    ASSERT_NOT_NULL(ba2 = ba_alloc_from_str(" World"));
    ASSERT_NOT_NULL(ba12 = ba_join(ba1, ba2));
    ASSERT_TRUE(ba_get_len(ba12) == strlen(str));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba12), str, ba_get_len(ba12)));

cleanup:

    BA_FREE(ba1, ba2, ba12);
}

static void test_ba_append(void)
{
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    const char *str = "Hello World";

    ASSERT_NOT_NULL(ba2 = ba_alloc_from_str(" World"));
    ASSERT_NOT_NULL(ba1 = ba_alloc_from_str("Hello"));
    ASSERT_RET_OK(ba_append(ba2, 0, 0, ba1));
    ASSERT_TRUE(ba_get_len(ba1) == strlen(str));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba1), str, ba_get_len(ba1)));

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_copy(void)
{
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    const char *str = "Hello";
    ASSERT_NOT_NULL(ba1 = ba_alloc_from_str(str));
    ASSERT_NOT_NULL(ba2 = ba_alloc_by_len(strlen(str)));
    ASSERT_RET_OK(ba_copy(ba1, 0, 0, ba2, 0));
    ASSERT_TRUE(ba_get_len(ba2) == strlen(str));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba2), str, ba_get_len(ba2)));

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_print(void)
{
    uint8_t data[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    char act_data[12] = {0};
    ByteArray *ba = ba_alloc_from_uint8(data, sizeof(data));
    FILE *f = NULL;
    size_t file_size = 0;
    char file_path[] = "file.txt";

    ASSERT_NOT_NULL(f = fopen(file_path, "w"));
    ASSERT_RET_OK(ba_print(f, ba));
    fclose(f);

    ASSERT_NOT_NULL(f = fopen(file_path, "r"));
    file_size = fread(act_data, 1, sizeof(act_data), f);
    ASSERT_EQUALS("010203040506", act_data, file_size);
    fclose(f);

    remove(file_path);

cleanup:

    ba_free(ba);
}

static void test_ba_cmp_different_length(void)
{
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;

    ASSERT_NOT_NULL(ba1 = ba_alloc_by_len(41));
    ASSERT_NOT_NULL(ba2 = ba_alloc_by_len(40));
    ASSERT_TRUE(ba_cmp(ba1, ba2) == 1);

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_cmp_with_null(void)
{
    const ErrorCtx *err_ctx;
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    const char *str = "abc";

    ASSERT_NOT_NULL(ba2 = ba_alloc_from_str(str));
    ASSERT_TRUE(ba_cmp(ba1, ba2) == -1);
    err_ctx = stacktrace_get_last();
    ASSERT_NOT_NULL(err_ctx);
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_swap(void)
{
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    const char *text1 = "abc";
    const char *text2 = "cba";
    ASSERT_NOT_NULL(ba1 = ba_alloc_from_str(text1));
    ASSERT_NOT_NULL(ba2 = ba_alloc_from_str(text2));
    ASSERT_RET_OK(ba_swap(ba1));
    ASSERT_TRUE(ba_get_len(ba2) == ba_get_len(ba1));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba2), ba_get_buf(ba1), ba_get_len(ba2)));

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_xor(void)
{
    ByteArray *ba1 = NULL;
    ByteArray *ba2 = NULL;
    uint32_t val_u32 = (uint32_t)0x04030201;
    uint32_t result = 0;
    ASSERT_NOT_NULL(ba1 = ba_alloc_from_uint32(&val_u32, 1));
    ASSERT_NOT_NULL(ba2 = ba_alloc_from_uint32(&val_u32, 1));
    ASSERT_RET_OK(ba_xor(ba1, ba2));
    ASSERT_TRUE(!memcmp(ba_get_buf(ba1), &result, ba_get_len(ba1)));

cleanup:
    BA_FREE(ba1, ba2);
}

static void test_ba_is_zero_null(void)
{
    ByteArray *ba = NULL;
    ASSERT_TRUE(ba_is_zero(ba));
}

static void test_ba_is_zero(void)
{
    ByteArray *ba = NULL;
    ASSERT_NOT_NULL(ba = ba_alloc());
    ASSERT_RET_OK(ba_set(ba, 0));
    ASSERT_TRUE(ba_is_zero(ba));

cleanup:
    ba_free(ba);
}

static void test_ba_change_len_null(void)
{
    ByteArray *ba = NULL;
    ba_change_len(ba, 1);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);
}

static void test_ba_get_buf_null(void)
{
    const ErrorCtx *err_ctx;
    ByteArray *ba = NULL;
    ASSERT_TRUE(ba_get_buf(ba) == NULL);
    err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);
}

void utest_byte_array(void)
{
    PR("%s\n", __FILE__);

    test_ba_alloc();
    test_ba_to_with_alloc();
    test_ba_trim_leading_zeros();
    test_ba_join();
    test_ba_append();
    test_ba_copy();
    test_ba_print();
    test_ba_to_file();
    test_ba_alloc_from_file_with_wrong_name();
    test_ba_to_file_with_wrong_name();
    test_ba_cmp_different_length();
    test_ba_cmp_with_null();
    test_ba_swap();
    test_ba_from_uint8();
    test_ba_from_uint32();
    test_ba_from_uint64();
    test_ba_xor();
    test_ba_is_zero_null();
    test_ba_is_zero();
    test_ba_get_buf_null();
    test_ba_change_len_null();
}
