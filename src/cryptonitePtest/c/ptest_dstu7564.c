/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>


#include "ptest.h"
#include "dstu7564.h"

#define time_check2(mode)   {                                                   \
    ByteArray *data = ba_alloc_by_len(data_size_byte);                          \
    ASSERT_NOT_NULL(data);                                                      \
    ASSERT_RET_OK(ba_set(data, 0x90));                                          \
    ASSERT_NOT_NULL(ctx = (Dstu7564Ctx*)dstu7564_alloc(DSTU7564_SBOX_1));       \
    ASSERT_RET_OK(dstu7564_init(ctx, mode));                                    \
    start_time = get_time();                                                    \
    for (i = 0; i < LOOP_NUM; i++) {                                            \
        ASSERT_RET_OK(dstu7564_update(ctx, data));                              \
    }                                                                           \
    ASSERT_RET_OK(dstu7564_final(ctx, &hash_code_ba));                          \
    add_time(builder, start_time, 0);                                           \
cleanup:                                                                        \
    BA_FREE(data, hash_code_ba);                                                \
    }

#define time_check2_kmac(mode) {                                                \
    ByteArray *key = ba_alloc_by_len(mode);                                     \
    ByteArray *data = ba_alloc_by_len(data_size_byte);                          \
    ASSERT_NOT_NULL(ctx = dstu7564_alloc(DSTU7564_SBOX_1));                     \
    ASSERT_RET_OK(ba_set(key, 0x02));                                           \
    ASSERT_RET_OK(ba_set(data, 0x05));                                          \
    ASSERT_RET_OK(dstu7564_init_kmac(ctx, key, mode));                          \
    start_time = get_time();                                                    \
    for (i = 0; i < LOOP_NUM; i++) {                                            \
        ASSERT_RET_OK(dstu7564_update_kmac(ctx, data));                         \
    }                                                                           \
    ASSERT_RET_OK(dstu7564_final_kmac(ctx, &hash_code_ba));                     \
    add_time(builder, start_time, 0);                                           \
cleanup:                                                                        \
    BA_FREE(key, data, hash_code_ba);                                           \
}

static void *test_speed_dstu7564_hash_48(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-48-HASH");
    time_check2(6);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_hash_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-256-HASH");
    time_check2(32);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_hash_384(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-384-HASH");
    time_check2(48);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_hash_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-512-HASH");
    time_check2(64);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_kmac_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-256-KMAC");
    time_check2_kmac(32);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_kmac_384(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-384-KMAC");
    time_check2_kmac(48);
    dstu7564_free(ctx);

    return NULL;
}

static void *test_speed_dstu7564_kmac_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    double start_time;
    size_t i = 0;

    add_mode_name(builder, "DSTU7564-512-KMAC");
    time_check2_kmac(64);
    dstu7564_free(ctx);

    return NULL;
}

void ptest_dstu7564_hash(TableBuilder *builder)
{
    ptest_pthread_generator(test_speed_dstu7564_hash_48, builder);
    ptest_pthread_generator(test_speed_dstu7564_hash_256, builder);
    ptest_pthread_generator(test_speed_dstu7564_hash_384, builder);
    ptest_pthread_generator(test_speed_dstu7564_hash_512, builder);
}

void ptest_dstu7564_kmac(TableBuilder *builder)
{
    ptest_pthread_generator(test_speed_dstu7564_kmac_256, builder);
    ptest_pthread_generator(test_speed_dstu7564_kmac_384, builder);
    ptest_pthread_generator(test_speed_dstu7564_kmac_512, builder);
}
