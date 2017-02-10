/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "md5.h"

static void *speed_test(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *)void_builder;
    ByteArray *hash_code_ba = NULL;
    ByteArray *data = ba_alloc_by_len(data_size_byte);
    Md5Ctx *ctx = NULL;
    double time;
    size_t i;
    ASSERT_RET_OK(ba_set(data, 0x34));

    add_mode_name(builder, "md5-hash");
    ctx = md5_alloc();
    time = get_time();
    for (i = 0; i < LOOP_NUM; i++) {
        ASSERT_RET_OK(md5_update(ctx, data));
    }
    ASSERT_RET_OK(md5_final(ctx, &hash_code_ba));

    add_time(builder, time, 0);

cleanup:

    BA_FREE(data, hash_code_ba);
    md5_free(ctx);

    return NULL;
}

void ptest_md5(TableBuilder *builder)
{
    ptest_pthread_generator(speed_test, builder);
}
