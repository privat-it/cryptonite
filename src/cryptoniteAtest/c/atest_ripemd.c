/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "hmac.h"
#include "ripemd_internal.h"

static HashTestCtx ripemd160_data[] = {
    {
        "",
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
    },
    {
        "a",
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
    },
    {
        "abc",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    },
    {
        "message digest",
        "5d0689ef49d2fae572b881b123a85ffa21595f36",
    },
    {
        "abcdefghijklmnopqrstuvwxyz",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    },
    {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    },
    {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcd",
        "0f7093269cc9b37651061efd7c69aa949d76d004"
    },
    {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcdABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcd",
        "26f085f2abb0ed709cdeb1a5bc421bbbcbc8e4ae"
    }
};

static HashTestCtx ripemd128_data[] = {
    {
        "",
        "cdf26213a150dc3ecb610f18f6b38b46"
    },
    {
        "a",
        "86be7afa339d0fc7cfc785e72f578d33"
    },
    {
        "abc",
        "c14a12199c66e4ba84636b0f69144c77"
    },
    {
        "message digest",
        "9e327b3d6e523062afc1132d7df9d1b8"
    },
    {
        "abcdefghijklmnopqrstuvwxyz",
        "fd2aa607f71dc8f510714922b371834e"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "a1aa0689d0fafa2ddc22e88b49133a06"
    },
    {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d1e959eb179c911faea4624c60c5c702"
    }
};

//static HmacTestCtx ripemd128_hmac_data[] = {
//        {
//                "",
//                "00112233445566778899aabbccddeeff",
//                "ad9db2c1e22af9ab5ca9dbe5a86f67dc",
//        },
//        {
//                "a",
//                "00112233445566778899aabbccddeeff",
//                "3bf448c762de00bcfa0310b11c0bde4c",
//        },
//        {
//                "abc",
//                "00112233445566778899aabbccddeeff",
//                "f34ec0945f02b70b8603f89e1ce4c78c",
//        },
//        {
//                "message digest",
//                "00112233445566778899aabbccddeeff",
//                "e8503a8aec2289d82aa0d8d445a06bdd",
//        },
//        {
//                "abcdefghijklmnopqrstuvwxyz",
//                "00112233445566778899aabbccddeeff",
//                "ee880b735ce3126065de1699cc136199",
//        },
//        {
//                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
//                "00112233445566778899aabbccddeeff",
//                "794daf2e3bdeea2538638a5ced154434",
//        },
//        {
//                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
//                "00112233445566778899aabbccddeeff",
//                "3a06eef165b23625247800be23e232b6",
//        },
//};
//
//static HmacTestCtx ripemd160_hmac_data[] = {
//        {
//                "",
//                "00112233445566778899aabbccddeeff01234567",
//                "cf387677bfda8483e63b57e06c3b5ecd8b7fc055",
//        },
//        {
//                "a",
//                "00112233445566778899aabbccddeeff01234567",
//                "0d351d71b78e36dbb7391c810a0d2b6240ddbafc",
//        },
//        {
//                "abc",
//                "00112233445566778899aabbccddeeff01234567",
//                "f7ef288cb1bbcc6160d76507e0a3bbf712fb67d6",
//        },
//        {
//                "message digest",
//                "00112233445566778899aabbccddeeff01234567",
//                "f83662cc8d339c227e600fcd636c57d2571b1c34",
//        },
//        {
//                "abcdefghijklmnopqrstuvwxyz",
//                "00112233445566778899aabbccddeeff01234567",
//                "843d1c4eb880ac8ac0c9c95696507957d0155ddb",
//        },
//        {
//                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
//                "00112233445566778899aabbccddeeff01234567",
//                "60f5ef198a2dd5745545c1f0c47aa3fb5776f881",
//        },
//        {
//                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
//                "00112233445566778899aabbccddeeff01234567",
//                "e49c136a9e5627e0681b808a3b97e6a6e661ae79",
//        }
//};

static void test_ripemd_core(HashTestCtx *test_data, RipemdVariant id)
{
    ByteArray *data = ba_alloc_from_str(test_data->data);
    ByteArray *expected = ba_alloc_from_le_hex_string(test_data->hash);
    ByteArray *actual = NULL;
    RipemdCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ripemd_alloc(id));
    ASSERT_RET_OK(ripemd_update(ctx, data));
    ASSERT_RET_OK(ripemd_final(ctx, &actual));

    CHECK_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(data, expected, actual);
    ripemd_free(ctx);
}

static void test_ripemd160_core(HashTestCtx *test_data)
{
    test_ripemd_core(test_data, RIPEMD_VARIANT_160);
}

static void test_ripemd128_core(HashTestCtx *test_data)
{
    test_ripemd_core(test_data, RIPEMD_VARIANT_128);
}

//static void test_ripemd_hmac_core(HmacTestCtx *test_data, RipemdVariant id)
//{
//    ByteArray *data = ba_alloc_from_str(test_data->data);
//    ByteArray *key = ba_alloc_from_le_hex_string(test_data->key);
//    ByteArray *expected = ba_alloc_from_le_hex_string(test_data->expected);
//    ByteArray *actual = NULL;
//    HmacCtx *ctx = NULL;
//
//    ASSERT_NOT_NULL(ctx = hmac_alloc_ripemd(id));
//    ASSERT_RET_OK(hmac_init(ctx, key));
//    ASSERT_RET_OK(hmac_update(ctx, data));
//    ASSERT_RET_OK(hmac_final(ctx, &actual));
//
//    CHECK_EQUALS_BA(expected, actual);
//
//    cleanup:
//
//    BA_FREE(data, expected, actual, key);
//    hmac_free(ctx);
//}

//static void test_ripemd160_hmac_core(HmacTestCtx *test_data)
//{
//    test_ripemd_hmac_core(test_data, RIPEMD_VARIANT_160);
//}
//
//static void test_ripemd128_hmac_core(HmacTestCtx *test_data)
//{
//    test_ripemd_hmac_core(test_data, RIPEMD_VARIANT_128);
//}

void atest_ripemd(void)
{
    size_t err_count = error_count;

    ATEST_CORE(ripemd128_data, test_ripemd128_core, sizeof(HashTestCtx));
    ATEST_CORE(ripemd160_data, test_ripemd160_core, sizeof(HashTestCtx));
//    ATEST_CORE(ripemd128_hmac_data, test_ripemd128_hmac_core, sizeof(HmacTestCtx));
//    ATEST_CORE(ripemd160_hmac_data, test_ripemd160_hmac_core, sizeof(HmacTestCtx));

    if (err_count == error_count) {
        msg_print_atest("RIPEMD", "[hash-128,160,hmac-128,160]", "OK");

    } else {
        msg_print_atest("RIPEMD", "", "FAILED");
    }
}
