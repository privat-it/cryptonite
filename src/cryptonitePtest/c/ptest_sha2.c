/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "hmac.h"
#include "sha2.h"

#define time_check2(sha2_alloc)   {                                             \
    ByteArray *data = ba_alloc_by_len(data_size_byte);                          \
    ba_set(data, 0x80);                                                         \
    ctx = sha2_alloc;                                                           \
    time = get_time();                                                          \
    for (i = 0; i < LOOP_NUM; i++) {                                            \
        ASSERT_RET_OK(sha2_update(ctx, data));                                  \
    }                                                                           \
    ASSERT_RET_OK(sha2_final(ctx, &hash_code_ba));                              \
    add_time(builder, time, 0);                                                 \
cleanup:                                                                        \
    BA_FREE(data, hash_code_ba);                                                \
}


static void *speed_test_sha224(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Sha2Ctx *ctx = NULL;
    double time;
    size_t i = 0;

    // Benchmark speed
    add_mode_name(builder, "sha224-hash");
    time_check2(sha2_alloc(SHA2_VARIANT_224));
    sha2_free(ctx);

    return NULL;
}

static void *speed_test_sha256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Sha2Ctx *ctx = NULL;
    double time;
    size_t i = 0;

    // Benchmark speed
    add_mode_name(builder, "sha256-hash");
    time_check2(sha2_alloc(SHA2_VARIANT_256));
    sha2_free(ctx);

    return NULL;
}

static void *speed_test_sha384(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Sha2Ctx *ctx = NULL;
    double time;
    size_t i = 0;

    // Benchmark speed
    add_mode_name(builder, "sha384-hash");
    time_check2(sha2_alloc(SHA2_VARIANT_384));
    sha2_free(ctx);

    return NULL;
}


static void *speed_test_sha512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Sha2Ctx *ctx = NULL;
    double time;
    size_t i = 0;

    // Benchmark speed
    add_mode_name(builder, "sha512-hash");
    time_check2(sha2_alloc(SHA2_VARIANT_512));
    sha2_free(ctx);

    return NULL;
}

static void *speed_test_hmac_224(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    HmacCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *hmac = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "SHA224-HMAC");
    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(28);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    ctx = hmac_alloc_sha2(SHA2_VARIANT_224);
    ASSERT_RET_OK(hmac_init(ctx, key_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(hmac_update(ctx, data_ba));
    }
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    add_time(builder, time, 0);
cleanup:
    hmac_free(ctx);
    ba_free(hmac);
    ba_free(key_ba);

    return NULL;
}

static void *speed_test_hmac_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    HmacCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *hmac = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "SHA256-HMAC");
    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(32);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    ctx = hmac_alloc_sha2(SHA2_VARIANT_256);
    ASSERT_RET_OK(hmac_init(ctx, key_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(hmac_update(ctx, data_ba));
    }
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    add_time(builder, time, 0);

cleanup:
    hmac_free(ctx);
    ba_free(hmac);
    ba_free(key_ba);

    return NULL;
}

static void *speed_test_hmac_384(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    HmacCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *hmac = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "SHA384-HMAC");
    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(48);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    ctx = hmac_alloc_sha2(SHA2_VARIANT_384);
    ASSERT_RET_OK(hmac_init(ctx, key_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(hmac_update(ctx, data_ba));
    }
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    add_time(builder, time, 0);
cleanup:
    hmac_free(ctx);
    ba_free(hmac);
    ba_free(key_ba);

    return NULL;
}

static void *speed_test_hmac_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    HmacCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *hmac = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "SHA512-HMAC");
    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(64);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    ctx = hmac_alloc_sha2(SHA2_VARIANT_512);
    ASSERT_RET_OK(hmac_init(ctx, key_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(hmac_update(ctx, data_ba));
    }
    ASSERT_RET_OK(hmac_final(ctx, &hmac));

    add_time(builder, time, 0);

cleanup:
    hmac_free(ctx);
    ba_free(hmac);
    ba_free(key_ba);

    return NULL;
}

void ptest_sha2(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test_sha224, builder);
    ptest_pthread_generator(speed_test_sha256, builder);
    ptest_pthread_generator(speed_test_sha384, builder);
    ptest_pthread_generator(speed_test_sha512, builder);
}

void ptest_sha2_hmac(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test_hmac_224, builder);
    ptest_pthread_generator(speed_test_hmac_256, builder);
    ptest_pthread_generator(speed_test_hmac_384, builder);
    ptest_pthread_generator(speed_test_hmac_512, builder);
}
