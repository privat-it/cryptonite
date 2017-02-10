/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "gost28147.h"

static const uint8_t GOST28147_SBOX_11[] = {
    0x4, 0xa, 0x9, 0x2, 0xd, 0x8, 0x0, 0xe, 0x6, 0xb, 0x1, 0xc, 0x7, 0xf, 0x5, 0x3,
    0xe, 0xb, 0x4, 0xc, 0x6, 0xd, 0xf, 0xa, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
    0x5, 0x8, 0x1, 0xd, 0xa, 0x3, 0x4, 0x2, 0xe, 0xf, 0xc, 0x7, 0x6, 0x0, 0x9, 0xb,
    0x7, 0xd, 0xa, 0x1, 0x0, 0x8, 0x9, 0xf, 0xe, 0x4, 0x6, 0xc, 0xb, 0x2, 0x5, 0x3,
    0x6, 0xc, 0x7, 0x1, 0x5, 0xf, 0xd, 0x8, 0x4, 0xa, 0x9, 0xe, 0x0, 0x3, 0xb, 0x2,
    0x4, 0xb, 0xa, 0x0, 0x7, 0x2, 0x1, 0xd, 0x3, 0x6, 0x8, 0x5, 0x9, 0xc, 0xf, 0xe,
    0xd, 0xb, 0x4, 0x1, 0x3, 0xf, 0x5, 0x9, 0x0, 0xa, 0xe, 0x7, 0x6, 0x8, 0x2, 0xc,
    0x1, 0xf, 0xd, 0x0, 0x5, 0x7, 0xa, 0x4, 0x9, 0x2, 0x3, 0xe, 0x6, 0xb, 0x8, 0xc
};

static void gost28147_usr_alloc_test(void)
{
    Gost28147Ctx *standart_sbox_ctx = NULL;
    Gost28147Ctx *usr_sbox_ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf");
    ByteArray *data = ba_alloc_from_le_hex_string("34c01533e37d1c56e9431604f57e37a18f90eb0333a33362");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("863e78dd2d60d13ce38f0f691f68f7feb99bb76c3073142d");
    ByteArray *enc_standart = NULL;
    ByteArray *enc_usr_sbox = NULL;
    ByteArray *sbox = NULL;

    sbox = ba_alloc_from_uint8(GOST28147_SBOX_11, sizeof(GOST28147_SBOX_11));

    ASSERT_NOT_NULL(standart_sbox_ctx = gost28147_alloc(GOST28147_SBOX_ID_11));
    ASSERT_NOT_NULL(usr_sbox_ctx = gost28147_alloc_user_sbox(sbox));

    ASSERT_RET_OK(gost28147_init_ecb(standart_sbox_ctx, key));
    ASSERT_RET_OK(gost28147_encrypt(standart_sbox_ctx, data, &enc_standart));

    ASSERT_EQUALS_BA(enc_expected, enc_standart);

    ASSERT_RET_OK(gost28147_init_ecb(usr_sbox_ctx, key));
    ASSERT_RET_OK(gost28147_encrypt(usr_sbox_ctx, data, &enc_usr_sbox));

    ASSERT_EQUALS_BA(enc_expected, enc_usr_sbox);

cleanup:

    BA_FREE(key, data, enc_expected, enc_standart, enc_usr_sbox, sbox);

    gost28147_free(usr_sbox_ctx);
    gost28147_free(standart_sbox_ctx);
}
static void gost28147_ecb_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf");
    ByteArray *data = ba_alloc_from_le_hex_string("34c01533e37d1c56e9431604f57e37a18f90eb0333a33362");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("863e78dd2d60d13ce38f0f691f68f7feb99bb76c3073142d");
    ByteArray *enc_actual = NULL;
    ByteArray *dec_actual = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_ecb(ctx, key));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data, &enc_actual));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual, &dec_actual));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, data, enc_expected, enc_actual, dec_actual);
}

static void gost28147_ctr_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data = ba_alloc_from_le_hex_string("0102030405060708090a0b0c0d0e0f101112131415161718");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");
    ByteArray *enc_actual = NULL;
    ByteArray *dec_actual = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data, &enc_actual));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual, &dec_actual));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, iv, data, enc_expected, enc_actual, dec_actual);
}

static void gost28147_ctr_test_copy_with_alloc(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data = ba_alloc_from_le_hex_string("0102030405060708090a0b0c0d0e0f101112131415161718");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");
    ByteArray *enc_actual = NULL;
    ByteArray *dec_actual = NULL;
    Gost28147Ctx *ctx_copy = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_NOT_NULL(ctx_copy = gost28147_copy_with_alloc(ctx));
    gost28147_free(ctx);
    ctx = NULL;
    ASSERT_RET_OK(gost28147_encrypt(ctx_copy, data, &enc_actual));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_init_ctr(ctx_copy, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx_copy, enc_actual, &dec_actual));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    gost28147_free(ctx_copy);
    BA_FREE(key, iv, data, enc_expected, enc_actual, dec_actual);
}

static void gost28147_ctr_2_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data = ba_alloc_from_le_hex_string("0102030405060708090a0b0c0d0e0f101112131415161718");
    ByteArray *data1 = ba_alloc_from_le_hex_string("010203");
    ByteArray *data2 = ba_alloc_from_le_hex_string("0405060708090a0b0c0d0e0f101112131415161718");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");
    ByteArray *enc_data1 = ba_alloc_from_le_hex_string("da21005efb");
    ByteArray *enc_data2 = ba_alloc_from_le_hex_string("ea34aa48d17ebf1c4f52a18eca42d3ff4b46f4");
    ByteArray *enc_actual = NULL;
    ByteArray *enc_actual1 = NULL;
    ByteArray *enc_actual2 = NULL;
    ByteArray *dec_actual = NULL;
    ByteArray *dec_actual1 = NULL;
    ByteArray *dec_actual2 = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data1, &enc_actual1));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data2, &enc_actual2));
    ASSERT_NOT_NULL(enc_actual = ba_join(enc_actual1, enc_actual2));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_data1, &dec_actual1));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_data2, &dec_actual2));
    ASSERT_NOT_NULL(dec_actual = ba_join(dec_actual1, dec_actual2));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, iv, data, data1, data2, enc_expected, enc_data1, enc_data2, enc_actual1, enc_actual2, dec_actual1,
            dec_actual2, enc_actual, dec_actual);
}

static void gost28147_ctr_3_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data = ba_alloc_from_le_hex_string(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string(
            "da21005efbea34aa48d17ebf1c4f52a18eca42d3ff4b46f40bd18016490ddff6e446981c559778e4273350c755e2113dd8c2533450b2d481d004af84b8daa2cc");
    ByteArray *enc_actual = NULL;
    ByteArray *dec_actual = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data, &enc_actual));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual, &dec_actual));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, iv, data, enc_expected, enc_actual, dec_actual);
}

static void gost28147_cfb1_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data = ba_alloc_from_le_hex_string("0102030405060708090a0b0c0d0e0f101112131415161718");
    ByteArray *enc_expected = ba_alloc_from_le_hex_string("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3");
    ByteArray *enc_actual = NULL;
    ByteArray *dec_actual = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data, &enc_actual));
    ASSERT_EQUALS_BA(enc_expected, enc_actual);

    ASSERT_RET_OK(gost28147_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual, &dec_actual));
    ASSERT_EQUALS_BA(data, dec_actual);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, iv, data, enc_expected, enc_actual, dec_actual);
}

static void gost28147_cfb2_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("0102030401020304010203040102030401020304010203040102030401020304");
    ByteArray *data2 = ba_alloc_from_le_hex_string("01020304");
    ByteArray *enc_actual1 = NULL;
    ByteArray *enc_actual2 = NULL;
    ByteArray *dec_actual1 = NULL;
    ByteArray *dec_actual2 = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);

    ASSERT_RET_OK(gost28147_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data1, &enc_actual1));
    ASSERT_RET_OK(gost28147_encrypt(ctx, data2, &enc_actual2));

    ASSERT_RET_OK(gost28147_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual1, &dec_actual1));
    ASSERT_RET_OK(gost28147_decrypt(ctx, enc_actual2, &dec_actual2));

    ASSERT_EQUALS_BA(data1, dec_actual1);
    ASSERT_EQUALS_BA(data2, dec_actual2);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, iv, data1, data2, enc_actual1, enc_actual2, dec_actual1, dec_actual2);
}

static void gost28147_mac_test(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("0100000002000000030000000400000005000000060000000700000008000000");
    ByteArray *data = ba_alloc_from_le_hex_string("d1ce841aa50de523b0ab76646f0d1ee8ae02aa0c4e8eafb3");
    ByteArray *mac_exp = ba_alloc_from_le_hex_string("7e4a9667");
    ByteArray *mac_act = NULL;

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    ASSERT_RET_OK(gost28147_init_mac(ctx, key));
    ASSERT_RET_OK(gost28147_update_mac(ctx, data));
    ASSERT_RET_OK(gost28147_final_mac(ctx, &mac_act));
    ASSERT_EQUALS_BA(mac_exp, mac_act);

cleanup:

    gost28147_free(ctx);
    BA_FREE(key, data, mac_exp, mac_act);
}

void utest_gost28147(void)
{
    PR("%s\n", __FILE__);

    gost28147_usr_alloc_test();
    gost28147_ecb_test();
    gost28147_ctr_test();
    gost28147_ctr_2_test();
    gost28147_ctr_3_test();
    gost28147_cfb1_test();
    gost28147_cfb2_test();
    gost28147_mac_test();

    gost28147_ctr_test_copy_with_alloc();
}
