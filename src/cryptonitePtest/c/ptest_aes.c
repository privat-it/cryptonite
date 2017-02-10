/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "aes.h"


#define speed_test_loop(eng_mode, mode)  {                                      \
    ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(eng_mode));                        \
    ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));                 \
    ASSERT_RET_OK(ba_set(key_ba, 0x80));                                        \
    ASSERT_RET_OK(ba_set(data_ba, 0x90));                                       \
    time = get_time();                                                          \
    ASSERT_NOT_NULL(ctx = aes_alloc());                                         \
    ASSERT_RET_OK(aes_init_ecb(ctx, key_ba));                                   \
    for (i = 0; i < LOOP_NUM; i++) {                                            \
        ASSERT_RET_OK(aes_encrypt(ctx, data_ba, &cipher_ba));                   \
        ba_free(cipher_ba);                                                     \
        cipher_ba = NULL;                                                       \
    }                                                                           \
    add_time(builder, time, 0);                                                 \
cleanup:                                                                        \
    BA_FREE(key_ba, data_ba, cipher_ba);                                        \
    aes_free(ctx);                                                              \
    return NULL;                                                                \
}

static void *aes_ecb_128(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    AesCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *cipher_ba = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "AES-256-ECB");
    speed_test_loop(16, "ECB");
}

static void *aes_ecb_192(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    AesCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *cipher_ba = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "AES-192-ECB");
    speed_test_loop(24, "ECB");
}


static void *aes_ecb_256(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    AesCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *cipher_ba = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "AES-256-ECB");
    speed_test_loop(32, "ECB");
}

void ptest_aes(TableBuilder *builder)
{
    ptest_pthread_generator(aes_ecb_128, builder);
    ptest_pthread_generator(aes_ecb_192, builder);
    ptest_pthread_generator(aes_ecb_256, builder);
}
