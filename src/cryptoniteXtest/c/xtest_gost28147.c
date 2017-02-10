/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "gcrypt.h"
#include "openssl/gost.h"

#include "xtest.h"
#include "gost28147.h"

typedef enum {
    ECB_256 = 2,
} GOST28147_MODS;

static int gost_ecb(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    Gost28147Ctx *ctx_cryptonite = NULL;
    GOST2814789_KEY *ctx_ossl = NULL;
    gcry_cipher_hd_t hd;
    size_t tot_errors = 0;
    size_t i, j;
    double time;


    /*ecb test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "gost28147-ecb");

    /*OPENSSL*/
    ctx_ossl = malloc(sizeof (GOST2814789_KEY));
    result_ossl = malloc(data_size_byte);
    time = get_time();
    Gost2814789_set_key(ctx_ossl, (const unsigned char*) &ctx->CipherType.AES.keys[ECB_256], 256);
    Gost2814789_set_sbox(ctx_ossl, 821);
    for (j = 0; j < LOOP_NUM; j++) {
        for (i = 0; i < data_size_byte; i += 8) {
            Gost2814789_ecb_encrypt(&ctx->data[i], &result_ossl[i], ctx_ossl, 1);
        }
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);
    free(result_ossl);
    /*END OPENSSL*/
    /*GCRYPTO*/
    gcry_cipher_open(&hd, GCRY_CIPHER_GOST28147, GCRY_CIPHER_MODE_ECB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_256], 32);
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_gcrypt);
        result_gcrypt = malloc(data_size_byte);
        gcry_cipher_encrypt(hd, result_gcrypt, data_size_byte, ctx->data, data_size_byte);
    }

    add_time(ctx_tb, time, GCRYPT);

    res_gcrypt_ba = ba_alloc_from_uint8(result_gcrypt, data_size_byte);
    free(result_gcrypt);
    gcry_cipher_close(hd);
    /*end GCRYPTO*/

    /*CRYPTONITE*/
    ctx_cryptonite = gost28147_alloc(GOST28147_SBOX_ID_11);
    time = get_time();
    gost28147_init_ecb(ctx_cryptonite, ctx->CipherType.AES.key_256_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        gost28147_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    /*END CRYPTONITE*/

    xtest_check();

    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);
    gost28147_free(ctx_cryptonite);
    result_gcrypt = NULL;

    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int gost_ctr(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *res_ossl_ba = NULL;
    ByteArray *iv_ba = NULL;
    Gost28147Ctx *ctx_cryptonite = NULL;
    GOST2814789_KEY *ctx_ossl = NULL;
    size_t tot_errors = 0;
    size_t i, j;
    int cnt_num = 0;
    double time;

    uint8_t iv[8];
    uint8_t cnt_buf[32];

    memset(iv, 0, 8);
    memset(cnt_buf, 0, 32);
    iv_ba = ba_alloc_from_uint8(iv, 8);
    /*ecb test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "gost28147-ctr");

    /*OPENSSL*/
    ctx_ossl = malloc(sizeof (GOST2814789_KEY));
    result_ossl = malloc(data_size_byte);
    time = get_time();
    Gost2814789_set_key(ctx_ossl, (const unsigned char*) &ctx->CipherType.AES.keys[ECB_256], 256);
    Gost2814789_set_sbox(ctx_ossl, 821);
    for (j = 0; j < LOOP_NUM; j++) {
        Gost2814789_cnt_encrypt(ctx->data, result_ossl, data_size_byte, ctx_ossl, iv, cnt_buf, &cnt_num);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);
    free(result_ossl);
    /*END OPENSSL*/

    /*CRYPTONITE*/
    ctx_cryptonite = gost28147_alloc(GOST28147_SBOX_ID_11);
    time = get_time();
    gost28147_init_ctr(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        gost28147_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    /*END CRYPTONITE*/

    if (!equals_ba(res_ba, res_ossl_ba)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, OPENSSL);
        tot_errors++;
    }

    BA_FREE(res_ba, res_ossl_ba);
    gost28147_free(ctx_cryptonite);

    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int gost_cfb(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *res_ossl_ba = NULL;
    ByteArray *iv_ba = NULL;
    Gost28147Ctx *ctx_cryptonite = NULL;
    GOST2814789_KEY *ctx_ossl = NULL;
    size_t tot_errors = 0;
    size_t i, j;
    int cnt_num = 0;
    double time;

    uint8_t iv[8];
    uint8_t cnt_buf[32];

    memset(iv, 0, 8);
    memset(cnt_buf, 0, 32);
    iv_ba = ba_alloc_from_uint8(iv, 8);
    /*ecb test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "gost28147-cfb");

    /*OPENSSL*/
    ctx_ossl = malloc(sizeof (GOST2814789_KEY));
    result_ossl = malloc(data_size_byte);
    time = get_time();
    Gost2814789_set_key(ctx_ossl, (const unsigned char*) &ctx->CipherType.AES.keys[ECB_256], 256);
    Gost2814789_set_sbox(ctx_ossl, 821);
    for (j = 0; j < LOOP_NUM; j++) {
        Gost2814789_cfb64_encrypt(ctx->data, result_ossl, data_size_byte, ctx_ossl, iv, &cnt_num, 1);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);
    free(result_ossl);
    /*END OPENSSL*/

    /*CRYPTONITE*/
    ctx_cryptonite = gost28147_alloc(GOST28147_SBOX_ID_11);
    time = get_time();
    gost28147_init_cfb(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        gost28147_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    /*END CRYPTONITE*/

    if (!equals_ba(res_ba, res_ossl_ba)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, OPENSSL);
        tot_errors++;
    }

    BA_FREE(res_ba, res_ossl_ba);
    gost28147_free(ctx_cryptonite);

    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

void xtest_gost28147(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    AES_generete_data(xtest_ctx);

    gost_ecb(xtest_ctx, ctx);
    xtest_table_print(ctx);

    gost_ctr(xtest_ctx, ctx);
    xtest_table_print(ctx);

    gost_cfb(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}

