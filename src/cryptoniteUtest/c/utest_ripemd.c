/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "ripemd_internal.h"
#include "hmac.h"

static void ripemd128_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("7e9f53a26cfb83a7a351134066518136");
    ByteArray *hash = NULL;
    RipemdCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_128));
    ASSERT_RET_OK(ripemd_update(ctx, data));
    ASSERT_RET_OK(ripemd_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    ripemd_free(ctx);
}

static void ripemd160_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("7a4010ca51658e91c17b837c82dc0202f07e9f6a");
    ByteArray *hash = NULL;
    RipemdCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_160));
    ASSERT_RET_OK(ripemd_update(ctx, data));
    ASSERT_RET_OK(ripemd_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    ripemd_free(ctx);
}

static void ripemd160_hash2(void)
{
    ByteArray *data = ba_alloc_from_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcd");
    ByteArray *exp = ba_alloc_from_le_hex_string("0f7093269cc9b37651061efd7c69aa949d76d004");
    ByteArray *hash = NULL;
    RipemdCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_160));
    ASSERT_RET_OK(ripemd_update(ctx, data));
    ASSERT_RET_OK(ripemd_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    ripemd_free(ctx);
}

static void ripemd160_hash3(void)
{
    ByteArray *data =
            ba_alloc_from_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcdABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789abcd");
    ByteArray *exp = ba_alloc_from_le_hex_string("26f085f2abb0ed709cdeb1a5bc421bbbcbc8e4ae");
    ByteArray *hash = NULL;
    RipemdCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = ripemd_alloc(RIPEMD_VARIANT_160));
    ASSERT_RET_OK(ripemd_update(ctx, data));
    ASSERT_RET_OK(ripemd_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    ripemd_free(ctx);
}

void utest_ripemd(void)
{
    PR("%s\n", __FILE__);
    ripemd128_hash();
    ripemd160_hash();
    ripemd160_hash2();
    ripemd160_hash3();
}
