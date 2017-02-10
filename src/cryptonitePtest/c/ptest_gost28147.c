/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "gost28147.h"

static void *speed_test_ecb(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf");
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    ByteArray *cip_code_ba = NULL;
    double time;
    size_t i = 0;
    add_mode_name(builder, "gost28147-ecb");

    ba_set(data, 0x80);
    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    ASSERT_RET_OK(gost28147_init_ecb(ctx, key));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(gost28147_encrypt(ctx, data, &cip_code_ba));
        ba_free(cip_code_ba);
        cip_code_ba = NULL;
    }

    add_time(builder, time, 0);

cleanup:
    ba_free(key);
    BA_FREE(data, cip_code_ba);
    gost28147_free(ctx);

    return NULL;

}

static void *speed_test_ctr(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf");
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    ByteArray *cip_code_ba = NULL;
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    double time;
    size_t i = 0;

    add_mode_name(builder, "gost28147-ctr");

    ba_set(data, 0x80);

    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    ASSERT_RET_OK(gost28147_init_ctr(ctx, key, iv));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(gost28147_encrypt(ctx, data, &cip_code_ba));
        ba_free(cip_code_ba);
        cip_code_ba = NULL;
    }


    add_time(builder, time, 0);
cleanup:
    ba_free(key);
    BA_FREE(data, cip_code_ba, iv);
    gost28147_free(ctx);

    return NULL;
}

static void *speed_test_cfb(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    Gost28147Ctx *ctx = NULL;
    ByteArray *key = ba_alloc_from_le_hex_string("348724a4c1a67667153dde5933884250e3248c657d413b8c1c9ca09a56d968cf");
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    ByteArray *cip_code_ba = NULL;
    ByteArray *iv = ba_alloc_from_le_hex_string("0300000003000000");
    double time;
    size_t i = 0;

    add_mode_name(builder, "gost28147-cfb");
    ASSERT_RET_OK(ba_set(data, 0x80));
    ctx = gost28147_alloc(GOST28147_SBOX_ID_11);
    ASSERT_RET_OK(gost28147_init_cfb(ctx, key, iv));
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(gost28147_encrypt(ctx, data, &cip_code_ba));
        ba_free(cip_code_ba);
        cip_code_ba = NULL;
    }
    add_time(builder, time, 0);
cleanup:
    ba_free(key);
    BA_FREE(data, cip_code_ba, iv);
    gost28147_free(ctx);

    return NULL;
}

void ptest_gost28147(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test_ecb, builder);
    ptest_pthread_generator(speed_test_ctr, builder);
    ptest_pthread_generator(speed_test_cfb, builder);
}
