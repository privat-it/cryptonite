/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "gcrypt.h"
#include "openssl/gost.h"

#include "xtest.h"
#include "gost34_311.h"

typedef enum {
    ECB_256 = 2,
} GOST28147_MODS;

static int gost34311_xtest(XtestSt *ctx, TableBuilder *ctx_tb)
{
    GOSTR341194_CTX *ctx_ossl = NULL;
    ByteArray *res_ba = NULL;
    uint8_t *result_gcrypt = NULL;
    uint8_t *result_openssl = NULL;
    uint8_t *data_gcrypt = NULL;
    ByteArray *res_gcrypt_ba = NULL;
    ByteArray *res_ossl_ba = NULL;
    Gost34311Ctx *ctx_cryptonite = NULL;
    size_t tot_errors = 0;
    double time;

    size_t i = 0;
    ByteArray *sync_ba;
    uint8_t sync[32] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    };

    /*ecb test*/
    res_ba = NULL;
    add_mode_name(ctx_tb, "gost34_311-hash");
    data_gcrypt = malloc(data_size_byte * LOOP_NUM);
    for (i = 0; i < LOOP_NUM; i++) {
        memcpy(&data_gcrypt[i * data_size_byte], ctx->data, data_size_byte);
    }
    /*GCRYPTO*/
    result_gcrypt = malloc(32);
    time = get_time();
    gcry_md_hash_buffer(GCRY_MD_GOSTR3411_94, result_gcrypt, data_gcrypt, data_size_byte * LOOP_NUM);

    add_time(ctx_tb, time, GCRYPT);

    res_gcrypt_ba = ba_alloc_from_uint8(result_gcrypt, 32);
    free(result_gcrypt);
    free(data_gcrypt);
    /*end GCRYPTO*/

    /*CRYPTONITE sbox_11*/
    sync_ba = ba_alloc_from_uint8(sync, sizeof (sync));
    ctx_cryptonite = gost34_311_alloc(GOST28147_SBOX_ID_11, sync_ba);
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        gost34_311_update(ctx_cryptonite, ctx->data_ba);
    }
    gost34_311_final(ctx_cryptonite, &res_ba);

    add_time(ctx_tb, time, CRYPTONITE);
    gost34_311_free(ctx_cryptonite);
    /*END CRYPTONITE*/

    /*OPENSSL*/
    result_openssl = malloc(32);
    time = get_time();
    ctx_ossl = malloc(sizeof (GOSTR341194_CTX));
    GOSTR341194_Init(ctx_ossl, 821);
    for (i = 0; i < LOOP_NUM; i++) {
        GOSTR341194_Update(ctx_ossl, ctx->data, data_size_byte);
    }
    GOSTR341194_Final(result_openssl, ctx_ossl);

    res_ossl_ba = ba_alloc_from_uint8(result_openssl, 32);
    free(result_openssl);
    add_time(ctx_tb, time, OPENSSL);
    /*END OPENSSL*/
    xtest_check();

    BA_FREE(res_ba, res_gcrypt_ba, res_ossl_ba);
    result_gcrypt = NULL;

    if (tot_errors > 0) {
        return 0;
    } else {
        return 1;
    }
}

void xtest_gost34_311(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    AES_generete_data(xtest_ctx);

    gost34311_xtest(xtest_ctx, ctx);
    xtest_table_print(ctx);
    
    xtest_alg_free(xtest_ctx);
}
