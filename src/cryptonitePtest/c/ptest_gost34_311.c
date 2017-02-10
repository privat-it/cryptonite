/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "gost34_311.h"

static void *speed_test(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    Gost34311Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    ByteArray *hash_code_ba = NULL;
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    double time;
    size_t i = 0;

    ASSERT_NOT_NULL(ctx = gost34_311_alloc(GOST28147_SBOX_ID_11, sync));

    ASSERT_RET_OK(ba_set(data, 0x0a));

    add_mode_name(builder, "gost34_311");
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(gost34_311_update(ctx, data));
    }
    ASSERT_RET_OK(gost34_311_final(ctx, &hash_code_ba));

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data, hash_code_ba, sync);
    gost34_311_free(ctx);

    return NULL;
}

void ptest_gost34_311(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test, builder);
}
