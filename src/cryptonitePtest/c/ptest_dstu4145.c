/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <time.h>

#include "ptest.h"
#include "dstu4145.h"

static void *dstu4145_speed_test_sign(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *key = ba_alloc_from_le_hex_string("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    ByteArray *hash = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *seed = ba_alloc_by_len(40);
    PrngCtx *prng = NULL;
    Dstu4145Ctx *ctx = NULL;
    double i = 0;
    double time;

    ba_set(seed, 0xfa);

    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    add_mode_name(builder, "DSTU4145_SIGN_M257_PB");
    ASSERT_RET_OK(dstu4145_init_sign(ctx, key, prng));
    time = get_time();
    do {
        i++;
        ba_free(r);
        ba_free(s);
        ASSERT_RET_OK(dstu4145_sign(ctx, hash, &r, &s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, i, 0);

cleanup:
    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(key, hash, r, s, seed);

    return NULL;
}

static void *dstu4145_speed_test_verify(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *qx = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *qy = ba_alloc_from_le_hex_string("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
    ByteArray *hash = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *r = ba_alloc_from_le_hex_string("290941DBA365068954FF2F64D070EA22A4DBE0DE5DA29012815AEFA24BDECA78");
    ByteArray *s = ba_alloc_from_le_hex_string("2880A0AEE660D183817F8B0C6DED68D1FBB0F0DA3B49E025A6AE5CB08D8D8D53");
    Dstu4145Ctx *ctx = NULL;
    double i = 0;
    double time;

    add_mode_name(builder, "DSTU4145_VERIFY_M257_PB");
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    i = 0;

    time = get_time();
    do {
        i++;
        ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, i, 0);

cleanup:
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash, r, s);

    return NULL;
}

void ptest_dstu4145(TableBuilder *builder)
{
    add_default_speed_measure(builder, OP_STRING_VALUE);

    ptest_pthread_generator(dstu4145_speed_test_sign, builder);
    ptest_pthread_generator(dstu4145_speed_test_verify, builder);

    add_default_speed_measure(builder, MB_STRING_VALUE);
}
