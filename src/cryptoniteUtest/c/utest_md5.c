/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "md5.h"

static void md5_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("bb97ee538c659feae1c136c545e83188");
    ByteArray *hash = NULL;
    Md5Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = md5_alloc());
    ASSERT_RET_OK(md5_update(ctx, data));
    ASSERT_RET_OK(md5_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    md5_free(ctx);
}

static void md5_hash_2(void)
{
    ByteArray *data = ba_alloc_from_str("000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *exp = ba_alloc_from_le_hex_string("949c4ec88ae01d7abf7618859b141f0d");
    ByteArray *hash = NULL;
    Md5Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = md5_alloc());
    ASSERT_RET_OK(md5_update(ctx, data));
    ASSERT_RET_OK(md5_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    md5_free(ctx);
}

#ifdef UTEST_FULL

static void md5_hash_3(void)
{
    ByteArray *data = ba_alloc_by_len(1024 * 1024);
    ByteArray *exp = ba_alloc_from_le_hex_string("aa559b4e3523a6c931f08f4df52d58f2");
    ByteArray *hash = NULL;
    Md5Ctx *ctx = NULL;
    int i = 0;

    ba_set(data, 0);
    ASSERT_NOT_NULL(ctx = md5_alloc());
    for (i = 0; i < 512; i++) {
        ASSERT_RET_OK(md5_update(ctx, data));
    }
    ASSERT_RET_OK(md5_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    md5_free(ctx);
}

#endif

void utest_md5(void)
{
    PR("%s\n", __FILE__);
    md5_hash();
    md5_hash_2();

#ifdef UTEST_FULL
    md5_hash_3();
#endif
}
