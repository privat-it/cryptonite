/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "openssl/md5.h"
#include "gcrypt.h"

#include "xtest.h"
#include "md5.h"

static int md5_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    ByteArray *res_ossl_ba = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ba = NULL;
    Md5Ctx *ctx_cryptonite = NULL;
    MD5_CTX *ctx_ossl = NULL;
    uint8_t res_openssl[20];
    uint8_t res_gcrypt[20];
    uint8_t *data_gcrypt = NULL;
    double time;

    size_t tot_errors = 0;
    size_t i = 0;

    /*MD5 test*/
    add_mode_name(ctx_tb, "md5-hash");
    /*Cryptonite*/
    time = get_time();
    ctx_cryptonite = md5_alloc();

    for (i = 0; i < LOOP_NUM; i++) {
        md5_update(ctx_cryptonite, ctx->data_ba);
    }
    md5_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    /*End Cryptonite*/
    /*OpenSSL*/
    time = get_time();
    ctx_ossl = malloc(sizeof (MD5_CTX));
    MD5_Init(ctx_ossl);
    for (i = 0; i < LOOP_NUM; i++) {
        MD5_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    MD5_Final(res_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(res_openssl, 16);
    add_time(ctx_tb, time, OPENSSL);
    /*End OpenSSL*/

    /*Libgcrypt*/
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_MD5, res_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    res_gcrypt_ba = ba_alloc_from_uint8(res_gcrypt, 16);
    add_time(ctx_tb, time, GCRYPT);
    /*End Libgcrypt*/

    xtest_check();

    BA_FREE(res_ossl_ba, res_ba, res_gcrypt_ba);
    free(ctx_ossl);
    md5_free(ctx_cryptonite);
    free(data_gcrypt);
    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

void xtest_md5(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    DES_generete_data(xtest_ctx);

    md5_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}
