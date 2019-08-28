/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "aes.h"
#include "utest.h"
#include "paddings.h"

static void test_aes_key_gen(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("00000000000000000000000000000000");
    ByteArray *key = NULL;
    ByteArray *cipher = NULL;
    ByteArray *enc = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_RET_OK(aes_generate_key(prng, 16, &key));
    ASSERT_NOT_NULL(key);

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    ASSERT_RET_OK(aes_decrypt(ctx, cipher, &enc));

    ASSERT_EQUALS_BA(data, enc);

cleanup:

    prng_free(prng);
    aes_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(enc);
    ba_free(cipher);
}

static void test_aes32_ecb(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172a");
    ByteArray *key = ba_alloc_from_le_hex_string("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("f3eed1bdb5d2a03c064b5a7e3db181f8");

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);

    ba_free(cipher);
    cipher = NULL;

    aes_decrypt(ctx, exp, &cipher);

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, exp, cipher);
}

static void test_aes24_ecb(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172a");
    ByteArray *key = ba_alloc_from_le_hex_string("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("bd334f1d6e45f25ff712a214571fa5cc");

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);

    ba_free(cipher);
    cipher = NULL;

    aes_decrypt(ctx, exp, &cipher);

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, exp, cipher);
}

static void test_aes16_ecb(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172a");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("3ad77bb40d7a3660a89ecaf32466ef97");

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);

    ba_free(cipher);
    cipher = NULL;

    aes_decrypt(ctx, exp, &cipher);

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, exp, cipher);
}

static void test_aes16_cfb(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172aae2d8a571e03");
    ByteArray *data2 =
            ba_alloc_from_le_hex_string("ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    aes_free(ctx);
}

static void test_aes16_ecb_data_is_divided(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172a");
    ByteArray *data2 = ba_alloc_from_le_hex_string("abababababababababababababababab");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *enc_data_exp = ba_alloc_from_le_hex_string("3ad77bb40d7a3660a89ecaf32466ef975170c5add70eb053de216641a9aae9e4");
    ByteArray *enc_data = NULL;
    ByteArray *enc_data1 = NULL;
    ByteArray *enc_data2 = NULL;
    ByteArray *dec_data1 = NULL;
    ByteArray *dec_data2 = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &enc_data));
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx); ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &enc_data1));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &enc_data2));
    ba_copy(enc_data1, 0, 0, enc_data, 0);
    ba_copy(enc_data2, 0, 0, enc_data, 16);
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx); ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ecb(ctx, key));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data1, &dec_data1));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data2, &dec_data2));
    ASSERT_RET_OK(ba_append(dec_data2, 0, 0, dec_data1));
    ASSERT_EQUALS_BA(data, dec_data1);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, data1, data2, enc_data_exp, enc_data, enc_data1, enc_data2, dec_data1, dec_data2);
}

static void test_aes16_ctr_data_is_divided(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1bee2");
    ByteArray *data2 =
            ba_alloc_from_le_hex_string("2e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    ByteArray *expected =
            ba_alloc_from_le_hex_string("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
    ByteArray *result = NULL;
    ByteArray *result2 = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));
    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &result));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &result2));
    ASSERT_RET_OK(ba_append(result2, 0, 0, result));

    ASSERT_EQUALS_BA(result, expected);

    aes_free(ctx);

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, result, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    BA_FREE(key, data1, data2, plain, iv, result2, result, data, expected);
    aes_free(ctx);
}

static void test_aes16_cfb_data_is_divided(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1");
    ByteArray *data2 = ba_alloc_from_le_hex_string("bee22e409f96e93d7e117393172a");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("000102030405060708090a0b0c0d0e0f");
    ByteArray *expected = ba_alloc_from_le_hex_string("3b3fd92eb72dad20333449f8e83cfb4a");
    ByteArray *result = NULL;
    ByteArray *result2 = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));
    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &result));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &result2));
    ASSERT_RET_OK(ba_append(result2, 0, 0, result));

    ASSERT_EQUALS_BA(result, expected);

    aes_free(ctx);

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, result, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    aes_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(data1);
    ba_free(data2);
    ba_free(plain);
    ba_free(expected);
    ba_free(iv);
    ba_free(result2);
    ba_free(result);
}

static void test_aes16_ofb_data_is_divided(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1");
    ByteArray *data2 = ba_alloc_from_le_hex_string("bee22e409f96e93d7e117393172a");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("000102030405060708090a0b0c0d0e0f");
    ByteArray *expected = ba_alloc_from_le_hex_string("3b3fd92eb72dad20333449f8e83cfb4a");
    ByteArray *result = NULL;
    ByteArray *result2 = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));
    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &result));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &result2));
    ASSERT_RET_OK(ba_append(result2, 0, 0, result));

    ASSERT_EQUALS_BA(result, expected);

    aes_free(ctx);

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, result, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    aes_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(data1);
    ba_free(data2);
    ba_free(plain);
    ba_free(expected);
    ba_free(iv);
    ba_free(result2);
    ba_free(result);
}

static void test_aes16_ofb(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172aae2d8a571e03");
    ByteArray *data2 =
            ba_alloc_from_le_hex_string("ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    aes_free(ctx);
}

static void test_aes16_ctr(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *data1 = ba_alloc_from_le_hex_string("6bc1bee22e409f96e93d7e117393172aae2d8a571e03");
    ByteArray *data2 =
            ba_alloc_from_le_hex_string("ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &cipher));

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    aes_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    aes_free(ctx);
}

static void test_aes16_cbc_data_is_divided_without_padding(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("f69f2445df4f9b17ad2b417be66c3710");
    ByteArray *data2 = ba_alloc_from_le_hex_string("b2eb05e2c39be9fcda6c19078c6a9d1b");
    ByteArray *key = ba_alloc_from_le_hex_string("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    ByteArray *enc_data_exp = ba_alloc_from_le_hex_string("B2EB05E2C39BE9FCDA6C19078C6A9D1BE568F68194CF76D6174D4CC04310A854");
    ByteArray *iv = ba_alloc_from_le_hex_string("39F23369A9D9BACFA530E26304231461");
    ByteArray *enc_data = NULL;
    ByteArray *enc_data1 = NULL;
    ByteArray *enc_data2 = NULL;
    ByteArray *dec_data1 = NULL;
    ByteArray *dec_data2 = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data, &enc_data));
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx); ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &enc_data1));
    ASSERT_RET_OK(aes_encrypt(ctx, data2, &enc_data2));
    ba_copy(enc_data1, 0, 0, enc_data, 0);
    ba_copy(enc_data2, 0, 0, enc_data, 16);
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx); ctx = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data1, &dec_data1));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data2, &dec_data2));
    ASSERT_RET_OK(ba_append(dec_data2, 0, 0, dec_data1));
    ASSERT_EQUALS_BA(data, dec_data1);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, data1, data2, enc_data_exp, enc_data, enc_data1, enc_data2, dec_data1, dec_data2, iv);
}

static void test_aes16_cbc_data_is_divided_with_padding(void)
{
    AesCtx *ctx = NULL;
    ByteArray *data = NULL;
    ByteArray *data1 = ba_alloc_from_le_hex_string("f69f2445df4f9b17ad2b417be66c3710");
    ByteArray *data2 = ba_alloc_from_le_hex_string("b2eb05e2c39be9fcda6c19078c6a");
    ByteArray *data2_expected = ba_alloc_from_le_hex_string("b2eb05e2c39be9fcda6c19078c6a0202");
    ByteArray *key = ba_alloc_from_le_hex_string("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    ByteArray *enc_data_exp = ba_alloc_from_le_hex_string("B2EB05E2C39BE9FCDA6C19078C6A9D1B78AABE25027288DB0D76060A9A84D5EF");
    ByteArray *iv = ba_alloc_from_le_hex_string("39F23369A9D9BACFA530E26304231461");
    ByteArray *enc_data = NULL;
    ByteArray *data_padd = NULL;
    ByteArray *enc_data1 = NULL;
    ByteArray *enc_data2 = NULL;
    ByteArray *dec_data1 = NULL;
    ByteArray *dec_data2 = NULL;

    ASSERT_NOT_NULL(data = ba_join(data1, data2));

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));

    ASSERT_RET_OK(make_pkcs7_padding(data, (uint8_t)ba_get_len(iv), &data_padd));
    ASSERT_RET_OK(aes_encrypt(ctx, data_padd, &enc_data));
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx);
    ctx = NULL;
    ba_free(data_padd);
    data_padd = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_encrypt(ctx, data1, &enc_data1));
    ASSERT_RET_OK(make_pkcs7_padding(data2, (uint8_t)ba_get_len(iv), &data_padd));
    ASSERT_RET_OK(aes_encrypt(ctx, data_padd, &enc_data2));
    ba_copy(enc_data1, 0, 0, enc_data, 0);
    ba_copy(enc_data2, 0, 0, enc_data, 16);
    ASSERT_EQUALS_BA(enc_data_exp, enc_data);
    aes_free(ctx);
    ctx = NULL;
    ba_free(data_padd);
    data_padd = NULL;

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data1, &dec_data1));
    ASSERT_RET_OK(aes_decrypt(ctx, enc_data2, &dec_data2));
    ASSERT_EQUALS_BA(data1, dec_data1);
    ASSERT_EQUALS_BA(data2_expected, dec_data2);

cleanup:

    aes_free(ctx);
    BA_FREE(key, data, data1, data2, enc_data_exp, enc_data, enc_data1, enc_data2, dec_data1, dec_data2, data2_expected, data_padd, iv);
}

static void utest_aes_cbc_core(size_t iteration, size_t key_mode)
{
    AesCtx *ctx = NULL;
    ByteArray *tmp_data = ba_alloc_from_le_hex_string(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *tmp_key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *data = NULL;
    ByteArray *data_padd = NULL;
    ByteArray *key = NULL;

    ASSERT_NOT_NULL(data = ba_copy_with_alloc(tmp_data, iteration, 0));
    ASSERT_NOT_NULL(key = ba_copy_with_alloc(tmp_key, 0, key_mode));

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(make_pkcs7_padding(data, (uint8_t)ba_get_len(iv), &data_padd));
    ASSERT_RET_OK(aes_encrypt(ctx, data_padd, &cipher));

    aes_free(ctx);

    ASSERT_NOT_NULL(ctx = aes_alloc());
    ASSERT_RET_OK(aes_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(aes_decrypt(ctx, cipher, &plain));

    if ((iteration % 16) != 0) {
        ASSERT_TRUE(ba_get_buf(plain)[ba_get_len(plain) - 1] == (iteration % 16));
    }

cleanup:

    BA_FREE(key, data, plain, iv, cipher, tmp_data, tmp_key, data_padd);
    aes_free(ctx);
}

#define AES_CBC(mode){             \
int i = 0;                              \
    for(i = 1; i < 64; i++) {           \
        utest_aes_cbc_core(i, mode);   \
    }                                   \
}

void utest_aes(void)
{
    PR("%s\n", __FILE__);
    test_aes_key_gen();
    test_aes16_ecb_data_is_divided();
    test_aes16_ctr_data_is_divided();
    test_aes16_cfb_data_is_divided();
    test_aes16_ofb_data_is_divided();
    test_aes16_ecb();
    test_aes24_ecb();
    test_aes32_ecb();
    test_aes16_cbc_data_is_divided_without_padding();
    test_aes16_cbc_data_is_divided_with_padding();
    AES_CBC(16);
    AES_CBC(24);
    AES_CBC(32);
    test_aes16_cfb();
    test_aes16_ofb();
    test_aes16_ctr();
}
