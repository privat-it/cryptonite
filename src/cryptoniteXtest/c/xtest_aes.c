/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "gcrypt.h"

#include "xtest.h"
#include "aes.h"

typedef enum {
    ECB_128 = 0,
    ECB_192,
    ECB_256,
    CBC_128,
    CBC_192,
    CBC_256,
    CTR,
    CFB

} AES_MODS;

static int ctr_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_gcrypt_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *res_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    uint8_t *result_ossl = NULL;
    AesCtx *ctx_cryptonite = NULL;
    uint8_t iv[16];

    double time;
    unsigned int i;
    gcry_cipher_hd_t hd;
    const char *name = "aes256";
    size_t tot_errors = 0;
    uint8_t ecount_buf[64] = {1};
    unsigned int param = 0;
    int algo = gcry_cipher_map_name(name);

    memset(iv, 0, 16);
    memset(ecount_buf, 0, 20);
    iv_ba = ba_alloc_from_uint8(iv, 16);

    /*ctr-256 test*/
    add_mode_name(ctx_tb, "aes-256-ctr");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CTR, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_256], 32);
    gcry_cipher_setiv(hd, iv, 16);
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

    /*OPENSSL*/
    result_ossl = malloc(data_size_byte);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_ctr128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_256], iv, ecount_buf, &param);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);
    free(result_ossl);
    /*END OPENSSL*/

    ctx_cryptonite = aes_alloc();
    aes_init_ctr(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    xtest_check();

    aes_free(ctx_cryptonite);

    res_ba = NULL;
    memset(iv, 0, 16);
#ifdef XTEST_CHECK_FULL
    BA_FREE(res_gcrypt_ba, res_ba);
    /*cfb-192 test*/
    add_mode_name(ctx_tb, "aes-192-ctr");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CTR, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_192], 24);
    gcry_cipher_setiv(hd, iv, 16);
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

    ctx_cryptonite = aes_alloc();
    aes_init_ctr(ctx_cryptonite, ctx->CipherType.AES.key_192_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    if (!equals_ba(res_ba, res_gcrypt_ba)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, GCRYPT);
        tot_errors++;
    }

    aes_free(ctx_cryptonite);
    BA_FREE(res_gcrypt_ba, res_ba);
    memset(iv, 0, 16);
    res_ba = NULL;

    /*ctr-128 test*/
    add_mode_name(ctx_tb, "aes-128-ctr");
    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CTR, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_128], 16);
    gcry_cipher_setiv(hd, iv, 16);
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

    //    /*OPENSSL*/
    //    result_ossl = malloc(data_size_byte);
    //    time = get_time();
    //    for (i = 0; i < LOOP_NUM; i++) {
    //        free(result_ossl);
    //        result_ossl = malloc(data_size_byte);
    //        AES_ctr128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_128], iv, ecount_buf, &param);
    //    }
    //
    //    add_time(ctx_tb, time, OPENSSL);
    //    /*END OPENSSL*/
    ctx_cryptonite = aes_alloc();
    time = get_time();
    aes_init_ctr(ctx_cryptonite, ctx->CipherType.AES.key_128_ba, iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);


    if (!equals_ba(res_ba, res_gcrypt_ba)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, GCRYPT);
        tot_errors++;
    }

    aes_free(ctx_cryptonite);
    memset(iv, 0, 16);
    res_ba = NULL;
#endif
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba, iv_ba);
    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int ecb_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    uint8_t *result_ossl = NULL;
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    AesCtx *ctx_cryptonite = NULL;
    size_t i, j;
    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "aes128";
    size_t tot_errors = 0;
    double time;


    algo = gcry_cipher_map_name(name);
    /*ecb-256 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-256-ecb");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_ECB, 0);

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

    time = get_time();
    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[2], 256, &ctx->CipherType.AES.key_ossl[2]);
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        for (j = 0; j < data_size_byte; j += 16) {
            AES_ecb_encrypt(&ctx->data[j], &result_ossl[j], &ctx->CipherType.AES.key_ossl[ECB_256], 1);
        }
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();

    time = get_time();
    aes_init_ecb(ctx_cryptonite, ctx->CipherType.AES.key_256_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    free(result_ossl);
    result_ossl = NULL;
    result_gcrypt = NULL;
#ifdef XTEST_CHECK_FULL
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    /*ecb-192 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-192-ecb");

    /*GCRYPTO*/
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_ECB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_192], 24);
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

    time = get_time();
    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[1], 192, &ctx->CipherType.AES.key_ossl[1]);
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        for (j = 0; j < data_size_byte; j += 16) {
            AES_ecb_encrypt(&ctx->data[j], &result_ossl[j], &ctx->CipherType.AES.key_ossl[ECB_192], 1);
        }
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    time = get_time();
    aes_init_ecb(ctx_cryptonite, ctx->CipherType.AES.key_192_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    res_ba = NULL;
    result_gcrypt = NULL;
    /*ecb-128 test*/
    add_mode_name(ctx_tb, "aes-128-ecb");
    /*GCRYPTO*/

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_ECB, 0);
    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_128], 16);
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

    /*OSSL*/

    time = get_time();

    AES_set_encrypt_key((const uint8_t*) &ctx->CipherType.AES.keys[0], 128, &ctx->CipherType.AES.key_ossl[0]);
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        for (j = 0; j < data_size_byte; j += 16) {
            AES_ecb_encrypt(&ctx->data[j], &result_ossl[j], &ctx->CipherType.AES.key_ossl[ECB_128], 1);
        }
    }

    add_time(ctx_tb, time, OPENSSL);
    /*CRYPTONITE*/
    ctx_cryptonite = aes_alloc();

    time = get_time();

    aes_init_ecb(ctx_cryptonite, ctx->CipherType.AES.key_128_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    result_ossl = NULL;
#endif
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int cfb_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    uint8_t *result_gcrypt = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *res_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    AesCtx *ctx_cryptonite = NULL;
    uint8_t iv[16];
    size_t i;
    double time;

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "aes128";
    size_t tot_errors = 0;
    int param = 0;

    memset(iv, 0, 16);
    iv_ba = ba_alloc_from_uint8(iv, 16);
    algo = gcry_cipher_map_name(name);

    /*cfb-256 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-256-cfb");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_256], 32);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cfb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_256], iv, &param, AES_ENCRYPT);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_cfb(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    free(result_ossl);
    memset(iv, 0, 16);
    result_ossl = NULL;
#ifdef XTEST_CHECK_FULL
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    /*cfb-192 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-192-cfb");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_192], 24);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cfb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_192], iv, &param, 1);
    }

    add_time(ctx_tb, time, OPENSSL);
    ctx_cryptonite = aes_alloc();
    aes_init_cfb(ctx_cryptonite, ctx->CipherType.AES.key_192_ba, iv_ba);

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    memset(iv, 0, 16);
    result_ossl = NULL;
    res_ba = NULL;
    /*cfb-128 test*/
    add_mode_name(ctx_tb, "aes-128-cfb");
    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_128], 16);
    gcry_cipher_setiv(hd, iv, 16);
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

    result_ossl = malloc(data_size_byte);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cfb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_128], iv, &param, 1);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_cfb(ctx_cryptonite, ctx->CipherType.AES.key_128_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    memset(iv, 0, 16);
#endif
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba, iv_ba);
    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int cbc_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    uint8_t *result_gcrypt = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *res_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    AesCtx *ctx_cryptonite = NULL;
    uint8_t iv[16];
    size_t i;
    double time;

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "aes128";
    size_t tot_errors = 0;
    memset(iv, 0, 16);
    iv_ba = ba_alloc_from_uint8(iv, 16);
    algo = gcry_cipher_map_name(name);

    /*cbc-256 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-256-cbc");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_256], 32);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cbc_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_256], iv, 1);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_cbc(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    free(result_ossl);
    result_ossl = NULL;
    memset(iv, 0, 16);
#ifdef XTEST_CHECK_FULL
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    /*cbc-192 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-192-cbc");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_192], 24);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cbc_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_192], iv, 1);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_cbc(ctx_cryptonite, ctx->CipherType.AES.key_192_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    memset(iv, 0, 16);
    result_ossl = NULL;
    res_ba = NULL;
    /*cbc-128 test*/
    add_mode_name(ctx_tb, "aes-128-cbc");
    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_128], 16);
    gcry_cipher_setiv(hd, iv, 16);
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

    result_ossl = malloc(data_size_byte);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_cbc_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_128], iv, 1);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_cbc(ctx_cryptonite, ctx->CipherType.AES.key_128_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    memset(iv, 0, 16);

#endif
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba, iv_ba);
    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }
}

static int ofb_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    uint8_t *result_gcrypt = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    uint8_t *result_ossl = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *res_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    AesCtx *ctx_cryptonite = NULL;
    uint8_t iv[16];
    size_t i;
    double time;

    int param = 0;
    size_t tot_errors = 0;
    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "aes128";

    memset(iv, 0, 16);
    iv_ba = ba_alloc_from_uint8(iv, 16);
    algo = gcry_cipher_map_name(name);

    /*ofb-256 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-256-ofb");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_OFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_256], 32);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_ofb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_256], iv, &param);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_ofb(ctx_cryptonite, ctx->CipherType.AES.key_256_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);

    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    free(result_ossl);
    result_ossl = NULL;
    memset(iv, 0, 16);
#ifdef XTEST_CHECK_FULL
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    /*ofb-192 test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "aes-192-ofb");

    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_OFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_192], 24);
    gcry_cipher_setiv(hd, iv, 16);
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

    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_ofb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_192], iv, &param);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_ofb(ctx_cryptonite, ctx->CipherType.AES.key_192_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba);
    memset(iv, 0, 16);
    result_ossl = NULL;
    res_ba = NULL;
    /*ofb-128 test*/
    add_mode_name(ctx_tb, "aes-128-ofb");
    /*GCRYPTO*/
    result_gcrypt = malloc(data_size_byte);

    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_OFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.AES.keys[ECB_128], 16);
    gcry_cipher_setiv(hd, iv, 16);
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

    result_ossl = malloc(data_size_byte);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_ossl);
        result_ossl = malloc(data_size_byte);
        AES_ofb128_encrypt(ctx->data, result_ossl, data_size_byte, &ctx->CipherType.AES.key_ossl[ECB_128], iv, &param);
    }

    add_time(ctx_tb, time, OPENSSL);

    ctx_cryptonite = aes_alloc();
    aes_init_ofb(ctx_cryptonite, ctx->CipherType.AES.key_128_ba, iv_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        aes_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }

    add_time(ctx_tb, time, CRYPTONITE);
    res_ossl_ba = ba_alloc_from_uint8(result_ossl, data_size_byte);

    xtest_check();

    aes_free(ctx_cryptonite);
    memset(iv, 0, 16);
#endif
    BA_FREE(res_gcrypt_ba, res_ba, res_ossl_ba, iv_ba);
    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }
}

void xtest_aes(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    AES_generete_data(xtest_ctx);

    ecb_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    ctr_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    cfb_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    cbc_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    ofb_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}
