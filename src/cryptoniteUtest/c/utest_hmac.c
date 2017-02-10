/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "hmac.h"
//#include "ripemd_internal.h"

static const uint8_t GOST28147_SBOX[128] = {
    0xa, 0x9, 0xd, 0x6, 0xe, 0xb, 0x4, 0x5, 0xf, 0x1, 0x3, 0xc, 0x7, 0x0, 0x8, 0x2,
    0x8, 0x0, 0xc, 0x4, 0x9, 0x6, 0x7, 0xb, 0x2, 0x3, 0x1, 0xf, 0x5, 0xe, 0xa, 0xd,
    0xf, 0x6, 0x5, 0x8, 0xe, 0xb, 0xa, 0x4, 0xc, 0x0, 0x3, 0x7, 0x2, 0x9, 0x1, 0xd,
    0x3, 0x8, 0xd, 0x9, 0x6, 0xb, 0xf, 0x0, 0x2, 0x5, 0xc, 0xa, 0x4, 0xe, 0x1, 0x7,
    0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5, 0xb, 0x4, 0x3, 0xa,
    0x2, 0x8, 0x9, 0x7, 0x5, 0xf, 0x0, 0xb, 0xc, 0x1, 0xd, 0xe, 0xa, 0x3, 0x6, 0x4,
    0x3, 0x8, 0xb, 0x5, 0x6, 0x4, 0xe, 0xa, 0x2, 0xc, 0x1, 0x7, 0x9, 0xf, 0xd, 0x0,
    0x1, 0x2, 0x3, 0xe, 0x6, 0xd, 0xb, 0x8, 0xf, 0xa, 0xc, 0x5, 0x7, 0x9, 0x0, 0x4,
};

void test_hmac_md5(void)
{
    ByteArray *data = ba_alloc_from_str("Hi There");
    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ByteArray *exp = ba_alloc_from_le_hex_string("9294727a3638bb1c13f48ef8158bfc9d");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_md5());
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data, key, hmac);
    hmac_free(ctx);
}

void test_hmac_md5_2(void)
{
    ByteArray *data = ba_alloc_from_str("Test Using Larger Than Block-Size Key - Hash Key First");
    ByteArray *key =
            ba_alloc_from_le_hex_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *exp = ba_alloc_from_le_hex_string("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_md5());
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data, key, hmac);
    hmac_free(ctx);
}

//static void ripemd128_hmac(void)
//{
//    ByteArray *data = ba_alloc_from_str("Hi There");
//    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
//    ByteArray *exp = ba_alloc_from_le_hex_string("fbf61f9492aa4bbf81c172e84e0734db");
//    ByteArray *hmac = NULL;
//    HmacCtx *ctx = NULL;
//
//    ASSERT_NOT_NULL(ctx = hmac_alloc_ripemd(RIPEMD_VARIANT_128));
//    ASSERT_RET_OK(hmac_init(ctx, key));
//    ASSERT_RET_OK(hmac_update(ctx, data));
//    ASSERT_RET_OK(hmac_final(ctx, &hmac));
//
//    ASSERT_EQUALS_BA(exp, hmac);
//
//cleanup:
//
//    BA_FREE(exp, data, key, hmac);
//    hmac_free(ctx);
//}
//
//static void ripemd160_hmac(void)
//{
//    ByteArray *data = ba_alloc_from_str("Hi There");
//    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
//    ByteArray *exp = ba_alloc_from_le_hex_string("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");
//    ByteArray *hmac = NULL;
//    HmacCtx *ctx = NULL;
//
//    ASSERT_NOT_NULL(ctx = hmac_alloc_ripemd(RIPEMD_VARIANT_160));
//    ASSERT_RET_OK(hmac_init(ctx, key));
//    ASSERT_RET_OK(hmac_update(ctx, data));
//    ASSERT_RET_OK(hmac_final(ctx, &hmac));
//
//    ASSERT_EQUALS_BA(exp, hmac);
//
// cleanup:
//
//    BA_FREE(exp, data, key, hmac);
//    hmac_free(ctx);
//}

static void test_sha1_hmac(void)
{
    ByteArray *data = ba_alloc_from_str("Hello World");
    ByteArray *key = ba_alloc_from_le_hex_string("707172737475767778797a7b7c7d7e7f80818283");
    ByteArray *exp = ba_alloc_from_le_hex_string("2e492768aa339e32a9280569c5d026262b912431");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_sha1());
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data, key, hmac);
    hmac_free(ctx);
}

static void sha256_hmac(void)
{
    ByteArray *data = ba_alloc_from_str("Hi There");
    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ByteArray *exp = ba_alloc_from_le_hex_string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_256));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hmac);
    ba_free(key);
    hmac_free(ctx);
}

static void sha384_hmac(void)
{
    ByteArray *data = ba_alloc_from_str("Hi There");
    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_384));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));
    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data, key, hmac);
    hmac_free(ctx);
}

static void sha512_hmac(void)
{
    ByteArray *data = ba_alloc_from_str("Hi There");
    ByteArray *key = ba_alloc_from_le_hex_string("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_512));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data, key, hmac);
    hmac_free(ctx);
}

static void gost34311_hmac(void)
{
    ByteArray *data1 = ba_alloc_from_le_hex_string("CF818CADDFBDCDC940C8A530947427ED1A27949062602DA471ADA0D5CBFF32D8");
    ByteArray *data2 = ba_alloc_from_le_hex_string("00000001");
    ByteArray *key = ba_alloc_from_le_hex_string("646e333130373836646d6931");
    ByteArray *exp = ba_alloc_from_le_hex_string("20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15");
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, sync));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data1));
    ASSERT_RET_OK(hmac_update(ctx, data2));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data1, data2, key, hmac, sync);
    hmac_free(ctx);
}

static void gost34311_hmac_2(void)
{
    ByteArray *data1 = ba_alloc_from_le_hex_string("CF818CADDFBDCDC940C8A530947427ED1A27949062602DA471ADA0D5CBFF32D8");
    ByteArray *data2 = ba_alloc_from_le_hex_string("00000001");
    ByteArray *key = ba_alloc_from_le_hex_string("646e333130373836646d6931");
    ByteArray *exp = ba_alloc_from_le_hex_string("20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15");
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *user_sbox = ba_alloc_from_uint8(GOST28147_SBOX, sizeof(GOST28147_SBOX));
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_gost34_311_user_sbox(user_sbox, sync));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data1));
    ASSERT_RET_OK(hmac_update(ctx, data2));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ba_free(hmac);
    hmac = NULL;

    ASSERT_RET_OK(hmac_update(ctx, data1));
    ASSERT_RET_OK(hmac_update(ctx, data2));
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    ASSERT_EQUALS_BA(exp, hmac);

cleanup:

    BA_FREE(exp, data1, data2, key, hmac, sync, user_sbox);
    hmac_free(ctx);
}

void utest_hmac(void)
{
    PR("%s\n", __FILE__);

    test_hmac_md5();
    test_hmac_md5_2();
//    ripemd128_hmac();
//    ripemd160_hmac();
    test_sha1_hmac();
    sha256_hmac();
    sha384_hmac();
    sha512_hmac();
    gost34311_hmac();
    gost34311_hmac_2();
}
