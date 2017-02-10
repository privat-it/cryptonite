/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "gcrypt.h"

#include "xtest.h"
#include "des.h"

static int des3_ofb_atest_loop(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t* result_openssl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    DesCtx *ctx_cryptonite = NULL;
    size_t tot_errors = 0;
    double time;
    size_t i;
    int enc = 0;
    DES_cblock cb;
    /*des-ecb test*/
    add_mode_name(ctx_tb, "des3-ofb");

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "3des";

    /*OPENSSL*/
    result_openssl = malloc(data_size_byte);
    time = get_time();
    memcpy(cb, ctx->CipherType.DES.iv, 8);
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_openssl);
        result_openssl = malloc(data_size_byte);
        DES_ede3_ofb64_encrypt(ctx->data, result_openssl, (long)data_size_byte,
                &ctx->CipherType.DES.k1,
                &ctx->CipherType.DES.k2,
                &ctx->CipherType.DES.k3,
                &cb,
                &enc);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_openssl, data_size_byte);
    free(result_openssl);
    /*END OPENSSL*/

    /*GCRYPTO*/
    algo = gcry_cipher_map_name(name);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_OFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.DES.keys[0], 24);
    gcry_cipher_setiv(hd, ctx->CipherType.DES.iv, 8);
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
    ctx_cryptonite = des_alloc();

    time = get_time();
    des_init_ofb(ctx_cryptonite, ctx->CipherType.DES.key_ba, ctx->CipherType.DES.iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        des3_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    if (!equals_ba(res_ba, res_gcrypt_ba)) {
        add_error(ctx_tb, CRYPTONITE);
        add_error(ctx_tb, GCRYPT);
        tot_errors++;
    }

    des_free(ctx_cryptonite);
    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);

    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

static int des3_cbc_atest_loop(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_openssl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    DesCtx *ctx_cryptonite = NULL;
    DES_cblock cb;
    size_t tot_errors = 0;
    double time;
    size_t i;
    int enc = 1;
    /*des-ecb test*/
    add_mode_name(ctx_tb, "des3-cbc");

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "3des";

    /*OPENSSL*/
    result_openssl = malloc(data_size_byte);
    memcpy(cb, ctx->CipherType.DES.iv, 8);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_openssl);
        result_openssl = malloc(data_size_byte);
        DES_ede3_cbc_encrypt(ctx->data, result_openssl, (long)data_size_byte,
                &ctx->CipherType.DES.k1,
                &ctx->CipherType.DES.k2,
                &ctx->CipherType.DES.k3,
                &cb,
                enc);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_openssl, data_size_byte);
    free(result_openssl);
    /*END OPENSSL*/

    /*GCRYPTO*/
    algo = gcry_cipher_map_name(name);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.DES.keys[0], 24);
    gcry_cipher_setiv(hd, &ctx->CipherType.DES.iv[0], 8);
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
    ctx_cryptonite = des_alloc();

    time = get_time();
    des_init_cbc(ctx_cryptonite, ctx->CipherType.DES.key_ba, ctx->CipherType.DES.iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        des3_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    xtest_check();

    des_free(ctx_cryptonite);
    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);

    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

static int des3_cfb_atest_loop(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_openssl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    DesCtx *ctx_cryptonite = NULL;
    DES_cblock cb;
    size_t tot_errors = 0;
    double time;
    size_t i;
    int enc = 1;
    /*des-ecb test*/
    add_mode_name(ctx_tb, "des3-cfb");

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "3des";

    /*OPENSSL*/
    result_openssl = malloc(data_size_byte);
    memcpy(cb, ctx->CipherType.DES.iv, 8);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        free(result_openssl);
        result_openssl = malloc(data_size_byte);
        DES_ede3_cfb_encrypt(ctx->data, result_openssl, 64, (long)data_size_byte,
                &ctx->CipherType.DES.k1,
                &ctx->CipherType.DES.k2,
                &ctx->CipherType.DES.k3,
                &cb,
                enc);
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_openssl, data_size_byte);
    free(result_openssl);
    /*END OPENSSL*/

    /*GCRYPTO*/
    algo = gcry_cipher_map_name(name);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.DES.keys[0], 24);
    gcry_cipher_setiv(hd, &ctx->CipherType.DES.iv[0], 8);
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
    ctx_cryptonite = des_alloc();

    time = get_time();
    des_init_cfb(ctx_cryptonite, ctx->CipherType.DES.key_ba, ctx->CipherType.DES.iv_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        des3_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    xtest_check();

    des_free(ctx_cryptonite);
    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);

    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

static int des_ecb_atest_loop(XtestSt *ctx, TableBuilder *ctx_tb) {
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_openssl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    DesCtx *ctx_cryptonite = NULL;
    size_t tot_errors = 0;
    double time;
    size_t i, j;
    int enc = 1;
    /*des-ecb test*/
    add_mode_name(ctx_tb, "des-ecb");

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "des";

    /*OPENSSL*/
    result_openssl = malloc(data_size_byte);
    time = get_time();
    for (j = 0; j < LOOP_NUM; j++) {
        for (i = 0; i < data_size_byte; i += 8) {
            DES_ecb_encrypt((DES_cblock *) &ctx->data[i], (DES_cblock *) &result_openssl[i], &ctx->CipherType.DES.k1,
                            enc);
        }
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_openssl, data_size_byte);
    free(result_openssl);
    /*END OPENSSL*/

    /*GCRYPTO*/
    algo = gcry_cipher_map_name(name);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_ECB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.DES.keys[0], 8);
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
    ctx_cryptonite = des_alloc();
    time = get_time();
    des_init_ecb(ctx_cryptonite, ctx->CipherType.DES.key_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        des_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    xtest_check();

    des_free(ctx_cryptonite);
    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);

    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

static int des3_ecb_atest_loop(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_openssl = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    DesCtx *ctx_cryptonite = NULL;
    size_t tot_errors = 0;
    double time;
    size_t i, j;
    int enc = 1;
    /*des-ecb test*/
    add_mode_name(ctx_tb, "des3-ecb");

    gcry_cipher_hd_t hd;
    int algo = -1;
    const char *name = "3des";

    /*OPENSSL*/
    result_openssl = malloc(data_size_byte);
    time = get_time();
    for (j = 0; j < LOOP_NUM; j++) {
        for (i = 0; i < data_size_byte; i += 8) {
            DES_ecb3_encrypt((DES_cblock*) & ctx->data[i], (DES_cblock*) & result_openssl[i], &ctx->CipherType.DES.k1,
                    &ctx->CipherType.DES.k2,
                    &ctx->CipherType.DES.k3,
                    enc);
        }
    }

    add_time(ctx_tb, time, OPENSSL);
    res_ossl_ba = ba_alloc_from_uint8(result_openssl, data_size_byte);
    free(result_openssl);
    /*END OPENSSL*/

    /*GCRYPTO*/
    algo = gcry_cipher_map_name(name);
    gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_ECB, 0);

    time = get_time();
    gcry_cipher_setkey(hd, &ctx->CipherType.DES.keys[0], 24);
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
    ctx_cryptonite = des_alloc();
    time = get_time();
    des_init_ecb(ctx_cryptonite, ctx->CipherType.DES.key_ba);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_ba);
        des3_encrypt(ctx_cryptonite, ctx->data_ba, &res_ba);
    }


    add_time(ctx_tb, time, CRYPTONITE);

    xtest_check();

    des_free(ctx_cryptonite);
    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);

    if (tot_errors == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/**
 * Openssl docs:
 * https://www.openssl.org/docs/manmaster/crypto/des.html
 */
void xtest_des(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    DES_generete_data(xtest_ctx);

    des_ecb_atest_loop(xtest_ctx, ctx);
    xtest_table_print(ctx);
    des3_ecb_atest_loop(xtest_ctx, ctx);
    xtest_table_print(ctx);
    des3_ofb_atest_loop(xtest_ctx, ctx);
    xtest_table_print(ctx);
    des3_cfb_atest_loop(xtest_ctx, ctx);
    xtest_table_print(ctx);
    des3_cbc_atest_loop(xtest_ctx, ctx);
    xtest_table_print(ctx);
    
    xtest_alg_free(xtest_ctx);
}
