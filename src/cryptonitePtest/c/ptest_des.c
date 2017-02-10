/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "des.h"

static void *speed_test(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    DesCtx *ctx = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *cipher_ba = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "DES3-ECB");
    ASSERT_NOT_NULL(key_ba = ba_alloc_by_len(24));
    ASSERT_NOT_NULL(data_ba = ba_alloc_by_len(data_size_byte));
    ASSERT_RET_OK(ba_set(data_ba, 0x80));
    ASSERT_RET_OK(ba_set(key_ba, 0x90));
    time = get_time();
    ASSERT_NOT_NULL(ctx = des_alloc());
    ASSERT_RET_OK(des_init_ecb(ctx, key_ba));
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(des3_encrypt(ctx, data_ba, &cipher_ba));
        ba_free(cipher_ba);
        cipher_ba = NULL;
    }

    add_time(builder, time, 0);
cleanup:
    BA_FREE(key_ba, data_ba, cipher_ba);
    des_free(ctx);

    return NULL;
}

void ptest_des(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test, builder);
}
