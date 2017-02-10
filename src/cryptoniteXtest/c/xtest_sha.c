/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "openssl/sha.h"
#include "gcrypt.h"

#include "xtest.h"
#include "sha1.h"
#include "sha2.h"

static int sha1_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Sha1Ctx *ctx_cryptonite = NULL;
    SHA_CTX *ctx_ossl = NULL;
    uint8_t *data_gcrypt = NULL;
    uint8_t res_openssl[20];
    uint8_t res_gcrypt[20];
    double time;

    size_t tot_errors = 0;

    size_t i;
    /*sha1 test*/
    add_mode_name(ctx_tb, "sha1-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = sha1_alloc();
    for (i = 0; i < LOOP_NUM; i++) {
        sha1_update(ctx_cryptonite, ctx->data_ba);
    }
    sha1_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (SHA_CTX));
    SHA1_Init(ctx_ossl);
    for (i = 0; i < LOOP_NUM; i++) {
        SHA1_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    SHA1_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 20);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_SHA1, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 20);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    free(data_gcrypt);
    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    sha1_free(ctx_cryptonite);
    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int sha224_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Sha2Ctx *ctx_cryptonite = NULL;
    SHA256_CTX *ctx_ossl = NULL;
    uint8_t *data_gcrypt = NULL;
    uint8_t res_openssl[28];
    uint8_t res_gcrypt[28];
    double time;

    size_t tot_errors = 0;

    size_t i;
    /*hash-224 test*/
    add_mode_name(ctx_tb, "sha224-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = sha2_alloc(SHA2_VARIANT_224);
    for (i = 0; i < LOOP_NUM; i++) {
        sha2_update(ctx_cryptonite, ctx->data_ba);
    }
    sha2_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (SHA256_CTX));
    SHA224_Init(ctx_ossl);
    for (i = 0; i < LOOP_NUM; i++) {
        SHA224_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    SHA224_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 28);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_SHA224, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 28);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    sha2_free(ctx_cryptonite);
    free(data_gcrypt);

    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int sha256_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Sha2Ctx *ctx_cryptonite = NULL;
    SHA256_CTX *ctx_ossl = NULL;
    uint8_t res_openssl[32];
    uint8_t res_gcrypt[32];
    double time;
    uint8_t *data_gcrypt = NULL;
    size_t tot_errors = 0;

    size_t i;

    /*hash-224 test*/
    add_mode_name(ctx_tb, "sha256-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = sha2_alloc(SHA2_VARIANT_256);
    for (i = 0; i < LOOP_NUM; i++) {
        sha2_update(ctx_cryptonite, ctx->data_ba);
    }
    sha2_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (SHA256_CTX));
    SHA256_Init(ctx_ossl);
    for (i = 0; i < LOOP_NUM; i++) {
        SHA256_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    SHA256_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 32);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_SHA256, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 32);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    sha2_free(ctx_cryptonite);
    free(data_gcrypt);
    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int sha384_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Sha2Ctx *ctx_cryptonite = NULL;
    SHA512_CTX *ctx_ossl = NULL;
    uint8_t res_openssl[48];
    uint8_t res_gcrypt[48];
    double time;
    uint8_t *data_gcrypt = NULL;
    size_t tot_errors = 0;
    size_t i;


    /*hash-384 test*/
    add_mode_name(ctx_tb, "sha384-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = sha2_alloc(SHA2_VARIANT_384);
    for (i = 0; i < LOOP_NUM; i++) {
        sha2_update(ctx_cryptonite, ctx->data_ba);
    }
    sha2_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (SHA512_CTX));
    SHA384_Init(ctx_ossl);

    for (i = 0; i < LOOP_NUM; i++) {
        SHA384_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    SHA384_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 48);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_SHA384, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 48);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    sha2_free(ctx_cryptonite);
    free(data_gcrypt);
    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

static int sha512_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Sha2Ctx *ctx_cryptonite = NULL;
    SHA512_CTX *ctx_ossl = NULL;
    uint8_t res_openssl[64];
    uint8_t res_gcrypt[64];

    double time;
    uint8_t *data_gcrypt = NULL;
    size_t tot_errors = 0;
    size_t i;

    /*hash-512 test*/
    add_mode_name(ctx_tb, "sha512-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = sha2_alloc(SHA2_VARIANT_512);
    for (i = 0; i < LOOP_NUM; i++) {
        sha2_update(ctx_cryptonite, ctx->data_ba);
    }
    sha2_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (SHA512_CTX));
    SHA512_Init(ctx_ossl);
    for (i = 0; i < LOOP_NUM; i++) {
        SHA512_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    SHA512_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 64);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_SHA512, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 64);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    sha2_free(ctx_cryptonite);
    free(data_gcrypt);
    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

/*TODO: Add hmac test*/
void xtest_sha(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    SHA_generete_data(xtest_ctx);

    sha224_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    sha256_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    sha384_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    sha512_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    sha1_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}
