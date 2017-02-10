/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "gost28147.h"

static void test_ecb(void)
{
    ByteArray *actual_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *expected_ba = NULL;
    ByteArray *decrypt_ba = NULL;

    Gost28147Ctx *ctx = NULL;
    uint8_t key_ECB_1[] = {
        0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67,
        0x15, 0x3d, 0xde, 0x59, 0x33, 0x88, 0x42, 0x50,
        0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c,
        0x1c, 0x9c, 0xa0, 0x9a, 0x56, 0xd9, 0x68, 0xcf
    };
    uint8_t input_data_ECB_1[] = {
        0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56,
        0xe9, 0x43, 0x16, 0x04, 0xf5, 0x7e, 0x37, 0xa1,
        0x8f, 0x90, 0xeb, 0x03, 0x33, 0xa3, 0x33, 0x62
    };
    uint8_t expected_ECB_1[] = {
        0x86, 0x3e, 0x78, 0xdd, 0x2d, 0x60, 0xd1, 0x3c,
        0xe3, 0x8f, 0x0f, 0x69, 0x1f, 0x68, 0xf7, 0xfe,
        0xb9, 0x9b, 0xb7, 0x6c, 0x30, 0x73, 0x14, 0x2d
    };
    uint8_t key_ECB_2[] = {
        0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67,
        0x15, 0x3d, 0xde, 0x59, 0x33, 0x88, 0x42, 0x50,
        0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c,
        0x1c, 0x9c, 0xa0, 0x9a, 0x56, 0xd9, 0x68, 0xcf
    };
    uint8_t input_data_ECB_2[] = {
        0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56
    };
    uint8_t expected_ECB_2[] = {
        0x86, 0x3e, 0x78, 0xdd, 0x2d, 0x60, 0xd1, 0x3c
    };
    uint8_t key_ECB_3[] = {
        0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67,
        0x15, 0x3d, 0xde, 0x59, 0x33, 0x88, 0x42, 0x50,
        0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c,
        0x1c, 0x9c, 0xa0, 0x9a, 0x56, 0xd9, 0x68, 0xcf
    };
    uint8_t input_data_ECB_3[] = {
        0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56,
        0xe9, 0x43, 0x16, 0x04, 0xf5, 0x7e, 0x37, 0xa1,
        0x8f, 0x90, 0xeb, 0x03, 0x33, 0xa3, 0x33, 0x62
    };
    uint8_t expected_ECB_3[] = {
        0x86, 0x3e, 0x78, 0xdd, 0x2d, 0x60, 0xd1, 0x3c,
        0xe3, 0x8f, 0x0f, 0x69, 0x1f, 0x68, 0xf7, 0xfe,
        0xb9, 0x9b, 0xb7, 0x6c, 0x30, 0x73, 0x14, 0x2d
    };

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    key_ba = ba_alloc_from_uint8(key_ECB_1, sizeof (key_ECB_1));
    data_ba = ba_alloc_from_uint8(input_data_ECB_1, sizeof (input_data_ECB_1));
    expected_ba = ba_alloc_from_uint8(expected_ECB_1, sizeof (expected_ECB_1));

    ASSERT_RET_OK(gost28147_init_ecb(ctx, key_ba));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data_ba, &actual_ba));
    ASSERT_NOT_NULL(actual_ba);
    CHECK_EQUALS_BA(expected_ba, actual_ba);
    ASSERT_RET_OK(gost28147_decrypt(ctx, actual_ba, &decrypt_ba));
    CHECK_EQUALS_BA(data_ba, decrypt_ba);
    ba_free(actual_ba);
    ba_free(decrypt_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(expected_ba);
    gost28147_free(ctx);

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    key_ba = ba_alloc_from_uint8(key_ECB_2, sizeof (key_ECB_2));
    data_ba = ba_alloc_from_uint8(input_data_ECB_2, sizeof (input_data_ECB_2));
    expected_ba = ba_alloc_from_uint8(expected_ECB_2, sizeof (expected_ECB_2));

    ASSERT_RET_OK(gost28147_init_ecb(ctx, key_ba));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data_ba, &actual_ba));
    ASSERT_NOT_NULL(actual_ba);
    CHECK_EQUALS_BA(expected_ba, actual_ba);
    ASSERT_RET_OK(gost28147_decrypt(ctx, actual_ba, &decrypt_ba));
    CHECK_EQUALS_BA(data_ba, decrypt_ba);
    ba_free(actual_ba);
    ba_free(decrypt_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(expected_ba);
    gost28147_free(ctx);

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    key_ba = ba_alloc_from_uint8(key_ECB_3, sizeof (key_ECB_3));
    data_ba = ba_alloc_from_uint8(input_data_ECB_3, sizeof (input_data_ECB_3));
    expected_ba = ba_alloc_from_uint8(expected_ECB_3, sizeof (expected_ECB_3));

    ASSERT_RET_OK(gost28147_init_ecb(ctx, key_ba));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data_ba, &actual_ba));
    ASSERT_NOT_NULL(actual_ba);
    CHECK_EQUALS_BA(expected_ba, actual_ba);
    ASSERT_RET_OK(gost28147_decrypt(ctx, actual_ba, &decrypt_ba));
    CHECK_EQUALS_BA(data_ba, decrypt_ba);

cleanup:

    ba_free(actual_ba);
    ba_free(decrypt_ba);
    ba_free(data_ba);
    ba_free(key_ba);
    ba_free(expected_ba);
    gost28147_free(ctx);
}

void atest_gost28147(void)
{
    size_t err_count = error_count;

    test_ecb();

    if (err_count == error_count) {
        msg_print_atest("GOST28147", "[ecb]", "OK");
    } else {
        msg_print_atest("GOST28147", "", "FAILED");
    }

    return;
}
