/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "crypto_cache.h"
#include "utest.h"
#include "dstu4145.h"
#include "ecdsa.h"
#include "rs.h"
#include "pthread_internal.h"

static void test_crypto_cache_add_dstu4145_pb(void)
{
    Dstu4145Ctx *ctx = NULL;
    int a = 0;
    int *f = NULL;
    size_t f_len = 0;
    ByteArray *b = NULL;
    ByteArray *n = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M167_PB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_pb(f, f_len, a, b, n, px, py, 0x0505));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(f, f_len, a, b, n, px, py));
    dstu4145_free(ctx);
    ctx = NULL;

    BA_FREE(b, n, px, py);
    free(f);
    b = NULL;
    n = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_PB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_pb(f, f_len, a, b, n, px, py, 0x3030));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(f, f_len, a, b, n, px, py));
    dstu4145_free(ctx);
    ctx = NULL;

    BA_FREE(b, n, px, py);
    free(f);
    f = NULL;
    b = NULL;
    n = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_pb(f, f_len, a, b, n, px, py, 0x3005));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_pb(f, f_len, a, b, n, px, py));

cleanup:

    crypto_cache_free();
    dstu4145_free(ctx);
    BA_FREE(b, n, px, py);
    free(f);
}

static void test_crypto_cache_add_dstu4145_onb(void)
{
    Dstu4145Ctx *ctx = NULL;
    int a = 0;
    int *f = NULL;
    size_t f_len = 0;
    ByteArray *b = NULL;
    ByteArray *n = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_onb(f[0], a, b, n, px, py, 0x0505));
    ASSERT_RET(RET_CTX_ALREADY_IN_CACHE, crypto_cache_add_dstu4145_onb(f[0], a, b, n, px, py, 0x3030));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_onb(f[0], a, b, n, px, py));
    dstu4145_free(ctx);
    ctx = NULL;

    BA_FREE(b, n, px, py);
    free(f);
    b = NULL;
    n = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_ONB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_onb(f[0], a, b, n, px, py, 0x3030));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_onb(f[0], a, b, n, px, py));
    dstu4145_free(ctx);
    ctx = NULL;

    BA_FREE(b, n, px, py);
    free(f);
    f = NULL;
    b = NULL;
    n = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M191_ONB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_dstu4145_onb(f[0], a, b, n, px, py, 0x3005));
    dstu4145_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = dstu4145_alloc_onb(f[0], a, b, n, px, py));

cleanup:

    crypto_cache_free();
    dstu4145_free(ctx);
    BA_FREE(b, n, px, py);
    free(f);
}

static void test_crypto_cache_add_dstu4145(void)
{
    Dstu4145Ctx *ctx = NULL;

    ASSERT_RET_OK(crypto_cache_add_any_new(0x0505));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    dstu4145_free(ctx);
    ctx = NULL;

    ASSERT_RET_OK(crypto_cache_add_dstu4145(DSTU4145_PARAMS_ID_M163_PB, 0x0505));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    dstu4145_free(ctx);
    ctx = NULL;

    ASSERT_RET_OK(crypto_cache_add_dstu4145(DSTU4145_PARAMS_ID_M233_ONB, 0x0505));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M233_ONB));
    dstu4145_free(ctx);
    ctx = NULL;

    ASSERT_RET_OK(crypto_cache_add_dstu4145(DSTU4145_PARAMS_ID_M173_PB, 0x0505));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_PB));

cleanup:

    crypto_cache_free();
    crypto_cache_add_any_new(0);
    dstu4145_free(ctx);
}

static void test_crypto_cache_add_ecdsa(void)
{
    ByteArray *p = NULL;
    ByteArray *a = NULL;
    ByteArray *b = NULL;
    ByteArray *q = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    EcdsaCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_RET_OK(ecdsa_get_params(ctx, &p, &a, &b, &q, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_ecdsa(p, a, b, q, px, py, 0x0505));
    ASSERT_RET(RET_CTX_ALREADY_IN_CACHE, crypto_cache_add_ecdsa(p, a, b, q, px, py, 0x5005));
    ecdsa_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ecdsa_free(ctx);
    ctx = NULL;

    BA_FREE(p, a, b, q, px, py);
    p = NULL;
    a = NULL;
    b = NULL;
    q = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P384_R1));
    ASSERT_RET_OK(ecdsa_get_params(ctx, &p, &a, &b, &q, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_ecdsa(p, a, b, q, px, py, 0x0505));
    ecdsa_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P384_R1));
    ecdsa_free(ctx);
    ctx = NULL;

    BA_FREE(p, a, b, q, px, py);
    p = NULL;
    a = NULL;
    b = NULL;
    q = NULL;
    px = NULL;
    py = NULL;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P256_R1));
    ASSERT_RET_OK(ecdsa_get_params(ctx, &p, &a, &b, &q, &px, &py));
    ASSERT_RET_OK(crypto_cache_add_ecdsa(p, a, b, q, px, py, 0x0505));
    ecdsa_free(ctx);
    ctx = NULL;
    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P256_R1));

cleanup:

    crypto_cache_free();
    BA_FREE(p, a, b, q, px, py);
    ecdsa_free(ctx);
}

void *crypto_cache_multithread_func(void *ctx)
{
    for (int i = 0; i < 10; i++) {
        crypto_cache_add_dstu4145(DSTU4145_PARAMS_ID_M163_PB + i, 0);
    }

    return NULL;
}

void *crypto_cache_multithread_func2(void *ctx)
{
    for (int i = 0; i < 10; i++) {
        Dstu4145Ctx *dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB + i);
        dstu4145_free(dstu_ctx);
    }

    return NULL;
}


#define THREADS_NUM 8

void test_crypto_cache_multithread(void)
{
    static pthread_t tid[THREADS_NUM];
    int i;

    for (i = 0; i < 8; i++) {
        pthread_create(&tid[i], NULL, crypto_cache_multithread_func, NULL);
    }

    for (i = 0; i < THREADS_NUM; i++) {
        pthread_join(tid[i], NULL);
    }

    crypto_cache_free();
    crypto_cache_add_any_new(0x0303);

    for (i = 0; i < 8; i++) {
        pthread_create(&tid[i], NULL, crypto_cache_multithread_func2, NULL);
    }

    for (i = 0; i < THREADS_NUM; i++) {
        pthread_join(tid[i], NULL);
    }

    crypto_cache_free();

}

void utest_crypto_cache(void)
{
    PR("%s\n", __FILE__);

    test_crypto_cache_add_dstu4145_pb();
    test_crypto_cache_add_dstu4145_onb();
    test_crypto_cache_add_dstu4145();
    test_crypto_cache_add_ecdsa();
    test_crypto_cache_multithread();

    crypto_cache_free();
}
