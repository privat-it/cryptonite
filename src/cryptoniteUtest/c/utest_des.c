/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "des.h"
#include "utest.h"
#include "paddings.h"

static void des_key_gen(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("00000000000000000000000000000000");
    ByteArray *key = NULL;
    ByteArray *cipher = NULL;
    ByteArray *enc = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_RET_OK(des_generate_key(prng, 16, &key));
    ASSERT_NOT_NULL(key);

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ecb(ctx, key));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    ASSERT_RET_OK(des_decrypt(ctx, cipher, &enc));

    ASSERT_EQUALS_BA(data, enc);

cleanup:

    prng_free(prng);
    des_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(enc);
    ba_free(cipher);
}

static void test_key8_gen(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *key = NULL;
    ByteArray *cipher = NULL;
    ByteArray *enc = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_RET_OK(des_generate_key(prng, 8, &key));
    ASSERT_NOT_NULL(key);

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ecb(ctx, key));
    ASSERT_RET_OK(des3_encrypt(ctx, data, &cipher));

    ASSERT_RET_OK(des3_decrypt(ctx, cipher, &enc));

    ASSERT_EQUALS_BA(data, enc);

cleanup:

    prng_free(prng);
    des_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(enc);
    ba_free(cipher);
}

static void des3_ecb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("00000000000000000000000000000000");
    ByteArray *key = ba_alloc_from_le_hex_string("800000000000000000000000000000000000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("95a8d72813daa94d95a8d72813daa94d");

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ecb(ctx, key));
    ASSERT_RET_OK(des3_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(des3_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    des_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void des_ecb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("00000000000000000000000000000000");
    ByteArray *key = ba_alloc_from_le_hex_string("800000000000000000000000000000000000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("95a8d72813daa94d95a8d72813daa94d");

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ecb(ctx, key));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(des_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    des_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void des_cbc(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("c45ed470da71572aa86afeedbfc279e9b8ba4f021a20a7e968fbc380e8dd29ac");
    ByteArray *key = ba_alloc_from_le_hex_string("b8417680b959409958ff376bd5238b7d42575e0e24e4dc74");
    ByteArray *iv = ba_alloc_from_le_hex_string("38f29c2e287de279");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    des_free(ctx);

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    des_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(iv);
    ba_free(cipher);
}

static void des_cfb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F722000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    des_free(ctx);
}

static void des3_cfb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F722000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des3_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cfb(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    des_free(ctx);
}

static void des_ofb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F72");
    ByteArray *data3 = ba_alloc_from_le_hex_string("2000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *cipher3 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *plain3 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des_encrypt(ctx, data2, &cipher2));
    ASSERT_RET_OK(des_encrypt(ctx, data3, &cipher3));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));
    ASSERT_RET_OK(ba_append(cipher3, 0, 0, cipher_stream));
    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des_decrypt(ctx, cipher2, &plain2));
    ASSERT_RET_OK(des_encrypt(ctx, cipher3, &plain3));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));
    ASSERT_RET_OK(ba_append(plain3, 0, 0, plain_stream));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, plain, iv, cipher, plain1, plain2, plain3, cipher1, cipher2, cipher3, cipher_stream,
            plain_stream,
            data1, data2, data3);
    des_free(ctx);
}

static void des3_ofb(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F72");
    ByteArray *data3 = ba_alloc_from_le_hex_string("2000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *cipher3 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *plain3 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des3_encrypt(ctx, data2, &cipher2));
    ASSERT_RET_OK(des3_encrypt(ctx, data3, &cipher3));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));
    ASSERT_RET_OK(ba_append(cipher3, 0, 0, cipher_stream));
    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ofb(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher2, &plain2));
    ASSERT_RET_OK(des3_encrypt(ctx, cipher3, &plain3));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));
    ASSERT_RET_OK(ba_append(plain3, 0, 0, plain_stream));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, data3, plain, iv, cipher, plain1, plain2, plain3, cipher1, cipher2, cipher3,
            cipher_stream, plain_stream);
    des_free(ctx);
}


static void des_ctr(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F722000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    des_free(ctx);
}

static void des3_ctr(void) {
    DesCtx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("37363534333231204E6F77206973207468652074696D6520666F722000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("37363534333231204E6F772069732074686520");
    ByteArray *data2 = ba_alloc_from_le_hex_string("74696D6520666F722000");
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEFF0E1D2C3B4A596870123456789ABCDEF");
    ByteArray *iv = ba_alloc_from_le_hex_string("0000000000000000");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *plain1 = NULL;
    ByteArray *plain2 = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *plain_stream = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data, &cipher));

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des3_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(des3_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(cipher, cipher_stream);

    des_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher1, &plain1));
    ASSERT_RET_OK(des3_decrypt(ctx, cipher2, &plain2));

    ASSERT_NOT_NULL(plain_stream = ba_join(plain1, plain2));

    ASSERT_EQUALS_BA(data, plain_stream);

cleanup:

    BA_FREE(key, data, data1, data2, plain, iv, cipher, plain1, plain2, cipher1, cipher2, cipher_stream, plain_stream);
    des_free(ctx);
}

static void utest_des3_cbc_core(size_t iteration, size_t key_mode) {
    DesCtx *ctx = NULL;
    ByteArray *tmp_data = ba_alloc_from_le_hex_string(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    ByteArray *tmp_key = ba_alloc_from_le_hex_string("2b7e151628aed2a6abf715882b7e151628aed2a6abf71588");
    ByteArray *iv = ba_alloc_from_le_hex_string("f0f1f2f3f4f5f6f7");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;
    ByteArray *data = NULL;
    ByteArray *key = NULL;
    ByteArray *data_pad = NULL;
    bool is_padded = false;

    ASSERT_NOT_NULL(data = ba_copy_with_alloc(tmp_data, iteration, 0));
    ASSERT_NOT_NULL(key = ba_copy_with_alloc(tmp_key, 0, key_mode));

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cbc(ctx, key, iv));

    is_padded = (ba_get_len(data) % ba_get_len(iv) != 0);
    if (is_padded) {
        ASSERT_RET_OK(make_pkcs7_padding(data, (uint8_t) ba_get_len(iv), &data_pad))
    } else {
        data_pad = ba_copy_with_alloc(data, 0, 0);
    }
    ASSERT_RET_OK(des_encrypt(ctx, data_pad, &cipher));

    des_free(ctx);
    ba_free(data_pad);
    data_pad = NULL;

    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(des_decrypt(ctx, cipher, &plain));

    if ((iteration % 8) != 0) {
        ASSERT_TRUE(ba_get_buf(plain)[ba_get_len(plain) - 1] == (iteration % 8));
    }

cleanup:

    BA_FREE(key, tmp_key, data, plain, iv, cipher, tmp_data, data_pad);
    des_free(ctx);
}

#define DES3_CBC(mode){             \
int i = 0;                              \
    for(i = 1; i < 64; i++) {           \
        utest_des3_cbc_core(i, mode);   \
    }                                   \
}

void utest_des() {
    PR("%s\n", __FILE__);
    des_key_gen();
    test_key8_gen();

    des_ecb();
    des_cbc();
    des_cfb();
    des_ofb();
    des_ctr();

    des3_ecb();
    DES3_CBC(8);
    DES3_CBC(16);
    DES3_CBC(24);
    des3_cfb();
    des3_ofb();
    des3_ctr();
}
