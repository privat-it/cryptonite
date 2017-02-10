/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "dstu7624.h"

static void *test_speed_ecb_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    size_t block_size;

    ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(16));
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    block_size = 16;
    add_mode_name(builder, "DSTU7624-128-128-ECB");
    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key_ba, block_size));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data_ba, key_ba, actual_ba);
    dstu7624_free(ctx);

    return NULL;
}

static void *test_speed_ecb_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    size_t block_size;

    ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(32));
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    block_size = 32;
    add_mode_name(builder, "DSTU7624-256-256-ECB");
    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key_ba, block_size));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba);

    return NULL;
}

static void *test_speed_ecb_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    size_t block_size;

    ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(64));
    ASSERT_RET_OK(ba_set(key_ba, 0x50));
    block_size = 64;
    add_mode_name(builder, "DSTU7624-512-512-ECB");
    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key_ba, block_size));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba);

    return NULL;
}

#define KEY_IV_ALLOC(mode)                                              \
ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));             \
ASSERT_RET_OK(ba_set(data_ba, 0x75));                                   \
ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(mode));                        \
ASSERT_RET_OK(ba_set(key_ba, 0x50));                                    \
ASSERT_NOT_NULL(iv_ba  = ba_alloc_by_len(mode));                        \
ASSERT_RET_OK(ba_set(key_ba, 0x40));                                    \
ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1))

static void *test_speed_ctr_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-128-128-CTR");
    KEY_IV_ALLOC(16);
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_ctr_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-256-256-CTR");
    KEY_IV_ALLOC(32);
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_ctr_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-512-512-CTR");
    KEY_IV_ALLOC(64);
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_cbc_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-128-128-CBC");
    KEY_IV_ALLOC(16);
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_cbc_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-256-256-CBC");
    KEY_IV_ALLOC(32);
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_cbc_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-512-512-CBC");
    KEY_IV_ALLOC(64);
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_ofb_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-128-128-OFB");
    KEY_IV_ALLOC(16);

    ASSERT_RET_OK(dstu7624_init_ofb(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_ofb_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-256-256-OFB");
    KEY_IV_ALLOC(32);
    ASSERT_RET_OK(dstu7624_init_ofb(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_ofb_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-512-512-OFB");
    KEY_IV_ALLOC(64);
    ASSERT_RET_OK(dstu7624_init_ofb(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}


static void *test_speed_cfb_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-128-128-CFB");
    KEY_IV_ALLOC(16);
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key_ba, iv_ba, 16));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_cfb_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-256-256-CFB");
    KEY_IV_ALLOC(32);
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key_ba, iv_ba, 32));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}

static void *test_speed_cfb_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    size_t i;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;

    add_mode_name(builder, "DSTU7624-512-512-CFB");
    KEY_IV_ALLOC(64);
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key_ba, iv_ba, 64));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    dstu7624_free(ctx);
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);

    return NULL;
}


#define test_dec_ecb(eng_mode)                                      \
    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));         \
    time = get_time();                                              \
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key_ba, eng_mode));        \
    for (i = 0; i < LOOP_NUM; i++) {                                \
        ASSERT_RET_OK(dstu7624_decrypt(ctx, data_ba, &actual_ba));  \
        ba_free(actual_ba);                                         \
        actual_ba = NULL;                                           \
    }                                                               \
    add_time(builder, time, 0);                                     \
cleanup:                                                            \
    ba_free(actual_ba)

static void *test_speed_ecb_dec_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    double time;

    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(16);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));

    add_mode_name(builder, "DSTU7624-ECB-128-dec");
    test_dec_ecb(16);
    dstu7624_free(ctx);
    ba_free(key_ba);
    ba_free(data_ba);

    return NULL;
}

static void *test_speed_ecb_dec_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    double time;

    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(32);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));

    add_mode_name(builder, "DSTU7624-ECB-256-dec");
    test_dec_ecb(32);
    dstu7624_free(ctx);
    ba_free(key_ba);
    ba_free(data_ba);

    return NULL;
}

static void *test_speed_ecb_dec_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;
    double time;

    data_ba = ba_alloc_by_len(data_size_byte);
    ASSERT_RET_OK(ba_set(data_ba, 0x75));
    key_ba = ba_alloc_by_len(64);
    ASSERT_RET_OK(ba_set(key_ba, 0x50));

    add_mode_name(builder, "DSTU7624-ECB-512-dec");
    test_dec_ecb(64);

    dstu7624_free(ctx);
    ba_free(key_ba);
    ba_free(data_ba);

    return NULL;
}

static void *test_speed_xts_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;

    KEY_IV_ALLOC(16);
    add_mode_name(builder, "DSTU7624-128-128-XTS");
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);
    dstu7624_free(ctx);

    return NULL;
}

static void *test_speed_xts_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;

    KEY_IV_ALLOC(32);

    add_mode_name(builder, "DSTU7624-256-256-XTS");
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);
    dstu7624_free(ctx);

    return NULL;
}

static void *test_speed_xts_512(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    double time;

    ByteArray *data_ba = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *actual_ba = NULL;
    ByteArray *iv_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t i = 0;

    KEY_IV_ALLOC(64);

    add_mode_name(builder, "DSTU7624-512-512-XTS");
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key_ba, iv_ba));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(dstu7624_encrypt(ctx, data_ba, &actual_ba));
        ba_free(actual_ba);
        actual_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data_ba, key_ba, actual_ba, iv_ba);
    dstu7624_free(ctx);

    return NULL;
}

void ptest_dstu7624_cipher(TableBuilder *builder)
{
    ptest_pthread_generator(test_speed_ecb_128, builder);
    ptest_pthread_generator(test_speed_ecb_256, builder);
    ptest_pthread_generator(test_speed_ecb_512, builder);

    ptest_pthread_generator(test_speed_ctr_128, builder);
    ptest_pthread_generator(test_speed_ctr_256, builder);
    ptest_pthread_generator(test_speed_ctr_512, builder);

    ptest_pthread_generator(test_speed_ofb_128, builder);
    ptest_pthread_generator(test_speed_ofb_256, builder);
    ptest_pthread_generator(test_speed_ofb_512, builder);

    ptest_pthread_generator(test_speed_cbc_128, builder);
    ptest_pthread_generator(test_speed_cbc_256, builder);
    ptest_pthread_generator(test_speed_cbc_512, builder);

    ptest_pthread_generator(test_speed_cfb_128, builder);
    ptest_pthread_generator(test_speed_cfb_256, builder);
    ptest_pthread_generator(test_speed_cfb_512, builder);

    ptest_pthread_generator(test_speed_xts_128, builder);
    ptest_pthread_generator(test_speed_xts_256, builder);
    ptest_pthread_generator(test_speed_xts_512, builder);

    ptest_pthread_generator(test_speed_ecb_dec_128, builder);
    ptest_pthread_generator(test_speed_ecb_dec_256, builder);
    ptest_pthread_generator(test_speed_ecb_dec_512, builder);
}
