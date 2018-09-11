//
// Created by paradaimu on 9/6/18.
//

#include <math_gfp_internal.h>
#include <gost3410_params_internal.h>
#include "utest.h"
#include "gost3410.h"

static void utest_get_pubkey(void)
{
    Gost3410Ctx *ctx = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *d = ba_alloc_from_be_hex_string("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28");
    ByteArray *expQx = ba_alloc_from_le_hex_string("0BD86FE5D8DB89668F789B4E1DBA8585C5508B45EC5B59D8906DDB70E2492B7F");
    ByteArray *expQy = ba_alloc_from_le_hex_string("DA77FF871A10FBDF2766D293C5D164AFBB3C7B973A41C885D11D70D689B4F126");

    ASSERT_NOT_NULL(ctx = gost3410_alloc(GOST3410_PARAMS_ID_1));

    ASSERT_RET_OK(gost3410_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_EQUALS_BA(expQx, qx);
    ASSERT_EQUALS_BA(expQy, qy);

cleanup:

    gost3410_free(ctx);
    ba_free(d);
    ba_free(expQx);
    ba_free(expQy);
    ba_free(qx);
    ba_free(qy);
}

static void utest_compress_decompress_pubkey(void)
{
    Gost3410Ctx *ctx = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *dqx = NULL;
    ByteArray *dqy = NULL;
    ByteArray *compressPubkey = NULL;
    int last_bit = 0;
    ByteArray *d = ba_alloc_from_be_hex_string("066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971");
    ByteArray *expQx = ba_alloc_from_le_hex_string("BBB78FA531C8382A95CF10B8A0ED5EC976E133469390C4EA143138822CF634FD");
    ByteArray *expQy = ba_alloc_from_le_hex_string("778CC3183E38EB00BBC65158893C4106079DF770E298A366F627B3217AA233B4");

    ASSERT_NOT_NULL(ctx = gost3410_alloc(GOST3410_PARAMS_ID_2));

    ASSERT_RET_OK(gost3410_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_EQUALS_BA(expQx, qx);
    ASSERT_EQUALS_BA(expQy, qy);

    ASSERT_RET_OK(gost3410_compress_pubkey(ctx, qx, qy, &compressPubkey, &last_bit));

    ASSERT_RET_OK(gost3410_decompress_pubkey(ctx, compressPubkey, last_bit, &dqx, &dqy));

    ASSERT_EQUALS_BA(expQx, dqx);
    ASSERT_EQUALS_BA(expQy, dqy);

cleanup:

    gost3410_free(ctx);
    ba_free(d);
    ba_free(expQx);
    ba_free(expQy);
    ba_free(qx);
    ba_free(qy);
    ba_free(compressPubkey);
    ba_free(dqx);
    ba_free(dqy);
}


static void utest_sign_verify(void)
{
    Gost3410Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *d = NULL;
    ByteArray *hash = NULL;
    ByteArray *seed = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    ASSERT_NOT_NULL(ctx = gost3410_alloc(GOST3410_PARAMS_ID_2));

    ASSERT_RET_OK(gost3410_set_opt_level(ctx, OPT_LEVEL_COMB_5_WIN_5));

    ASSERT_NOT_NULL(seed = ba_alloc_by_len(40));
    ASSERT_RET_OK(ba_set(seed, 0x09));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    ASSERT_NOT_NULL(d = ba_alloc_from_be_hex_string("066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971"));
    ASSERT_RET_OK(gost3410_init_sign(ctx, d, prng));

    ASSERT_NOT_NULL(hash = ba_alloc_from_le_hex_string("719BD04194B68A33CAE7F9500ADABA9268719266D9951D681CF84924AAAF975F"));
    ASSERT_RET_OK(gost3410_sign(ctx, hash, &r, &s));

    ASSERT_RET_OK(gost3410_get_pubkey(ctx, d, &qx, &qy));

    gost3410_free(ctx);
    ctx = NULL;

    ASSERT_NOT_NULL(ctx = gost3410_alloc(GOST3410_PARAMS_ID_2));
    ASSERT_RET_OK(gost3410_set_opt_level(ctx, OPT_LEVEL_COMB_11_WIN_5));

    ASSERT_RET_OK(gost3410_init_verify(ctx, qx, qy));

    ASSERT_RET_OK(gost3410_verify(ctx, hash, r, s));

cleanup:

    gost3410_free(ctx);
    prng_free(prng);
    ba_free(seed);
    ba_free(d);
    ba_free(hash);
    ba_free(r);
    ba_free(s);
    ba_free(qx);
    ba_free(qy);
}

static void utest_verify(void)
{
    Gost3410Ctx *ctx = NULL;
    ByteArray *hash = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    ASSERT_NOT_NULL(hash =  ba_alloc_from_be_hex_string("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5"));
    ASSERT_NOT_NULL(qx = ba_alloc_from_be_hex_string("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"));
    ASSERT_NOT_NULL(qy = ba_alloc_from_be_hex_string("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"));
    ASSERT_NOT_NULL(r =  ba_alloc_from_be_hex_string("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493"));
    ASSERT_NOT_NULL(s =  ba_alloc_from_be_hex_string("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40"));

    ASSERT_NOT_NULL(ctx = gost3410_alloc(GOST3410_PARAMS_ID_1));
    ASSERT_RET_OK(gost3410_set_opt_level(ctx, OPT_LEVEL_WIN_5_WIN_5));

    ASSERT_RET_OK(gost3410_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(gost3410_verify(ctx, hash, r, s));

cleanup:

    ba_free(qx);
    ba_free(qy);
    ba_free(r);
    ba_free(s);
    ba_free(hash);
    gost3410_free(ctx);
}

void utest_gost3410()
{
    PR("%s\n", __FILE__);

    utest_get_pubkey();
    utest_compress_decompress_pubkey();
    utest_verify();
    utest_sign_verify();
}