/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "sha1.h"

static void *speed_test(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *hash_code_ba = NULL;
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    Sha1Ctx *ctx = NULL;
    double time;
    size_t i = 0;

    add_mode_name(builder, "sha1-hash");

    ba_set(data, 0x80);
    ctx = sha1_alloc();
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(sha1_update(ctx, data));
    }
    ASSERT_RET_OK(sha1_final(ctx, &hash_code_ba));

    add_time(builder, time, 0);

cleanup:
    BA_FREE(data, hash_code_ba);
    sha1_free(ctx);

    return NULL;
}

void ptest_sha1(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test, builder);
}
