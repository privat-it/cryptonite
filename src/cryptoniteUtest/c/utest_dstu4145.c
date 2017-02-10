/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <string.h>

#include "crypto_cache.h"
#include "byte_array_internal.h"
#include "utest.h"
#include "dstu4145.h"
#include "dstu4145_params_internal.h"
#include "rs.h"

static const Dstu4145DefaultParamsCtx DSTU4145_PARAMS_M163_PB = {
    {163, 7, 6, 3, 0},
    1,
    {
        0x21, 0x5d, 0x45, 0xc1, 0x19, 0x8a, 0x63, 0x5e, 0x92, 0x03, 0xb4, 0x0a, 0x21, 0xc8, 0x2d, 0x2a,
        0x46, 0x08, 0x61, 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x4d, 0xf1, 0xbc, 0x39, 0x2d, 0x26, 0xe2, 0x2b, 0xc1, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0xbe, 0x23, 0x58, 0xf3, 0xa3, 0xf8, 0xda, 0x29, 0x72, 0x23, 0xc4, 0xa5, 0x83, 0xe9, 0x4c, 0xd7,
        0x5d, 0x5f, 0xf8, 0xe2, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x3a, 0x72, 0xcd, 0xe2, 0x0c, 0xe0, 0xf0, 0x3f, 0xd0, 0xd9, 0x84, 0x52, 0xb9, 0xd7, 0x51, 0x8c,
        0x8a, 0x00, 0x6f, 0x82, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    false
};

#ifdef UTEST_FULL

static void dstu4145_onb_to_pb_test(void)
{
    WordArray *actual = wa_alloc_from_be_hex_string("0000000000000001053bc43edb5401d73e045d608f6cd71a");
    WordArray *pb = wa_alloc_from_be_hex_string("00001cd30e064b7d1f84f2654dafefb6341a69ed2de6f7be");
    Dstu4145Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));
    ASSERT_RET_OK(onb_to_pb(ctx->params, actual));
    ASSERT_EQUALS_WA(pb, actual);

cleanup:

    dstu4145_free(ctx);
    wa_free(actual);
    wa_free(pb);
}

static void dstu4145_pb_to_onb_test(void)
{
    WordArray *actual = wa_alloc_from_be_hex_string("00001cd30e064b7d1f84f2654dafefb6341a69ed2de6f7be");
    WordArray *onb = wa_alloc_from_be_hex_string("0000000000000001053bc43edb5401d73e045d608f6cd71a");
    Dstu4145Ctx *ctx = NULL;

    ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB);
    pb_to_onb(ctx->params, actual);
    ASSERT_EQUALS_WA(onb, actual);

    dstu4145_free(ctx);
    wa_free(actual);
    wa_free(onb);
}

static void dstu4145_onb_to_pb_173(void)
{
    WordArray *pb = wa_alloc_from_be_hex_string("01eec7c8f700a6aedbd1461bfd4e13f7a34be03124b2");
    WordArray *onb = wa_alloc_from_be_hex_string("043D7E139319F43BA00944915740E1E6651B06E278C7");
    WordArray *actual = wa_copy_with_alloc(onb);
    Dstu4145Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));

    ASSERT_RET_OK(onb_to_pb(ctx->params, actual));
    ASSERT_EQUALS_WA(pb, actual);

    ASSERT_RET_OK(pb_to_onb(ctx->params, actual));
    ASSERT_EQUALS_WA(onb, actual);

cleanup:

    dstu4145_free(ctx);
    wa_free(actual);
    wa_free(pb);
    wa_free(onb);
}

static void dstu4145_onb_to_pb_179(void)
{
    WordArray *onb = wa_alloc_from_be_hex_string("19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB");
    WordArray *pb = wa_alloc_from_be_hex_string("0004c8a1d80932e32d11d5cc8c5c61d708d9c7ec4072c6e0");
    WordArray *actual = wa_copy_with_alloc(onb);
    Dstu4145Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_ONB));

    ASSERT_RET_OK(onb_to_pb(ctx->params, actual));
    ASSERT_EQUALS_WA(pb, actual);

    ASSERT_RET_OK(pb_to_onb(ctx->params, actual));
    ASSERT_EQUALS_WA(onb, actual);

cleanup:

    dstu4145_free(ctx);
    wa_free(actual);
    wa_free(pb);
    wa_free(onb);
}

static void dstu4145_onb_to_pb_431(void)
{
    WordArray *onb = wa_alloc_from_be_hex_string(
            "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299");
    WordArray *pb = wa_alloc_from_be_hex_string(
            "0000513dc8305b5444dca36bf9c383216d191f9457d222eb612dea8cc5a073e37e17ed41b01d8152af26d45d676c728f814ba7f6014e4d55");
    WordArray *actual = wa_copy_with_alloc(onb);
    Dstu4145Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB));

    ASSERT_RET_OK(onb_to_pb(ctx->params, actual));
    ASSERT_EQUALS_WA(pb, actual);

    ASSERT_RET_OK(pb_to_onb(ctx->params, actual));
    ASSERT_EQUALS_WA(onb, actual);

cleanup:

    dstu4145_free(ctx);
    wa_free(actual);
    wa_free(pb);
    wa_free(onb);
}

#endif

static void dstu4145_sign_test(void)
{
    ByteArray *key = ba_alloc_from_le_hex_string("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    ByteArray *qx = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *qy = ba_alloc_from_le_hex_string("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
    ByteArray *hash = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));

    ASSERT_RET_OK(dstu4145_init_sign(ctx, key, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx, hash, &r, &s));

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(key, qx, qy, hash, r, s, seed);
}

static void dstu4145_verify_test(void)
{
    Dstu4145Ctx *ctx = NULL;
    ByteArray *qx = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *qy = ba_alloc_from_le_hex_string("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
    ByteArray *hash = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *r = ba_alloc_from_le_hex_string("ace29a89ec34329abf529d109ca838c26b13cc0e14d8663071da94ab198e2e64");
    ByteArray *s = ba_alloc_from_le_hex_string("39b9c25ab0187694ec170221e9135405894bf439c9cefea7f23e4e1a974eca1b");

    ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));

cleanup:

    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash, r, s);
}

static void dstu4145_verify_367_test(void)
{
    Dstu4145Ctx *ctx = NULL;
    ByteArray *qx = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000007629f54b547bb74fe086e8f4be65602660ffb61b057176cebec137cad9994e3d3d7decb560bf01ebc47a8afee2af");
    ByteArray *qy = ba_alloc_from_be_hex_string(
            "00000000000000000000000000000000000024863fb306d78bdc760d15681d678a3e3f95edd5577ffa7eb25bc9d1d9319808ee65e7dc8410bb32eb6407da53ed");
    ByteArray *hash = ba_alloc_from_be_hex_string("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
    ByteArray *r = ba_alloc_from_be_hex_string(
            "1f8d88f2894b5789fb09078283b619f8ddd1057551141abb24ada18257936e136b223f10afdce8cb091a2f5f8bbe");
    ByteArray *s = ba_alloc_from_be_hex_string(
            "1cef3a08267d23bf64647a87dfb116756ff87d365149271d00fbb8947eb1f73fe9e75c63df18cf73f985a313cf32");

    ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M367_PB);

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));

cleanup:

    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash, r, s);
}

static void dstu4145_keys_test(void)
{
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *key = ba_alloc_from_le_hex_string("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    ByteArray *qx = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *qy = ba_alloc_from_le_hex_string("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
    ByteArray *q = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *d = NULL;
    ByteArray *qx_act = NULL;
    ByteArray *qy_act = NULL;
    ByteArray *q_act = NULL;

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));

    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, key, &qx_act, &qy_act));
    ASSERT_EQUALS_BA(qx, qx_act);
    ASSERT_EQUALS_BA(qy, qy_act);

    ASSERT_RET_OK(dstu4145_compress_pubkey(ctx, qx, qy, &q_act));
    ASSERT_EQUALS_BA(q, q_act);

    BA_FREE(qx_act, qy_act);
    qx_act = NULL;
    qy_act = NULL;
    ASSERT_RET_OK(dstu4145_decompress_pubkey(ctx, q_act, &qx_act, &qy_act));

    ASSERT_EQUALS_BA(qx, qx_act);
    ASSERT_EQUALS_BA(qy, qy_act);

cleanup:

    dstu4145_free(ctx);
    prng_free(prng);
    BA_FREE(d, key, qx, qy, q, qx_act, qy_act, q_act, seed);
}

static void dstu4145_dh_test(void)
{
    Dstu4145Ctx *ctx = NULL;
    ByteArray *key1 = ba_alloc_from_le_hex_string("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    ByteArray *key2 = ba_alloc_from_le_hex_string("124356567867897806288183f164044ec3cdbd00288856db40b4cdf07123230800");
    ByteArray *zx_exp = ba_alloc_from_le_hex_string(
            "85165e0486221b3bee3211ac63b3809b23ea2f8c63e8d38e55e99792694fbb3701");
    ByteArray *zy_exp = ba_alloc_from_le_hex_string(
            "0103c5b13001dc277d4dd5e9630e32f34073d145738bdb2e8e17b52a956a02a901");
    ByteArray *qx1 = NULL;
    ByteArray *qy1 = NULL;
    ByteArray *qx2 = NULL;
    ByteArray *qy2 = NULL;
    ByteArray *zx_act = NULL;
    ByteArray *zy_act = NULL;

    ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB);

    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, key1, &qx1, &qy1));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, key2, &qx2, &qy2));

    ASSERT_RET_OK(dstu4145_dh(ctx, true, key1, qx2, qy2, &zx_act, &zy_act));
    ASSERT_EQUALS_BA(zx_exp, zx_act);
    ASSERT_EQUALS_BA(zy_exp, zy_act);
    BA_FREE(zx_act, zy_act);
    zx_act = NULL;
    zy_act = NULL;

    ASSERT_RET_OK(dstu4145_dh(ctx, true, key2, qx1, qy1, &zx_act, &zy_act));
    ASSERT_EQUALS_BA(zx_exp, zx_act);
    ASSERT_EQUALS_BA(zy_exp, zy_act);
    BA_FREE(zx_act, zy_act);
    zx_act = NULL;
    zy_act = NULL;

cleanup:

    dstu4145_free(ctx);
    BA_FREE(key1, key2, zx_exp, zy_exp, qx1, qy1, qx2, qy2);
}

static void dstu4145_sign_core(Dstu4145ParamsId params_id, int opt_level)
{
    ByteArray *hash_ba = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    Dstu4145Ctx *ctx_copy = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    rs_std_next_bytes(seed);
    prng = prng_alloc(PRNG_MODE_DSTU, seed);
    ctx = dstu4145_alloc(params_id);
    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level));

    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_init_sign(ctx, d, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx, hash_ba, &r, &s));

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash_ba, r, s));

    BA_FREE(qx, qy, r, s, d);
    d = NULL;
    qx = NULL;
    qy = NULL;
    r = NULL;
    s = NULL;

    ASSERT_NOT_NULL(ctx_copy = dstu4145_copy_params_with_alloc(ctx));

    ASSERT_RET_OK(dstu4145_generate_privkey(ctx_copy, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx_copy, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_init_sign(ctx_copy, d, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx_copy, hash_ba, &r, &s));

    ASSERT_RET_OK(dstu4145_init_verify(ctx_copy, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx_copy, hash_ba, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    dstu4145_free(ctx_copy);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed);
}

#ifdef UTEST_FULL
static void dstu4145_sign_core_2(Dstu4145ParamsId params_id, int opt_level)
{
    ByteArray *hash_ba = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    rs_std_next_bytes(seed);
    prng = prng_alloc(PRNG_MODE_DSTU, seed);
    ctx = dstu4145_alloc(params_id);

    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level));
    ASSERT_RET_OK(dstu4145_init_sign(ctx, d, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx, hash_ba, &r, &s));

    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash_ba, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed);
}

static void dstu4145_sign_core_3(Dstu4145ParamsId params_id, int opt_level)
{
    ByteArray *hash_ba = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    rs_std_next_bytes(seed);
    prng = prng_alloc(PRNG_MODE_DSTU, seed);
    ctx = dstu4145_alloc(params_id);

    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_init_sign(ctx, d, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx, hash_ba, &r, &s));

    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level));
    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash_ba, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed);
}

static void dstu4145_sign_core_4(Dstu4145ParamsId params_id, int opt_level1, int opt_level2, int opt_level3)
{
    ByteArray *hash_ba = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    rs_std_next_bytes(seed);
    prng = prng_alloc(PRNG_MODE_DSTU, seed);
    ctx = dstu4145_alloc(params_id);

    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level1));
    ASSERT_RET_OK(dstu4145_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(dstu4145_get_pubkey(ctx, d, &qx, &qy));

    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level2));
    ASSERT_RET_OK(dstu4145_init_sign(ctx, d, prng));
    ASSERT_RET_OK(dstu4145_sign(ctx, hash_ba, &r, &s));

    ASSERT_RET_OK(dstu4145_set_opt_level(ctx, opt_level3));
    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(dstu4145_verify(ctx, hash_ba, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    BA_FREE(qx, qy, hash_ba, r, s, d, seed);
}
#endif

static void test_dstu4145_set_wrong_opt_level(Dstu4145ParamsId params_id, int opt_level)
{
    Dstu4145Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(params_id));
    dstu4145_set_opt_level(ctx, opt_level);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:

    dstu4145_free(ctx);
}

static void test_dstu4145_equals_params(void)
{
    Dstu4145Ctx *param_a = NULL;
    Dstu4145Ctx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_NOT_NULL(param_b = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_RET_OK(dstu4145_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(equals);

cleanup:

    dstu4145_free(param_a);
    dstu4145_free(param_b);
}

static void test_dstu4145_equals_params2(void)
{
    Dstu4145Ctx *param_a = NULL;
    Dstu4145Ctx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_NOT_NULL(param_b = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));
    ASSERT_RET_OK(dstu4145_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(!equals);

cleanup:

    dstu4145_free(param_a);
    dstu4145_free(param_b);
}

static void test_dstu4145_equals_params3(void)
{
    Dstu4145Ctx *param_a = NULL;
    Dstu4145Ctx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_NOT_NULL(param_b = dstu4145_alloc(DSTU4145_PARAMS_ID_M367_PB));
    ASSERT_RET_OK(dstu4145_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(!equals);

cleanup:

    dstu4145_free(param_a);
    dstu4145_free(param_b);
}

static void test_dstu4145_is_onb_params(void)
{
    Dstu4145Ctx *params = NULL;
    bool is_onb_params;
    ASSERT_NOT_NULL(params = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));
    ASSERT_RET_OK(dstu4145_is_onb_params(params,  &is_onb_params));
    ASSERT_TRUE(is_onb_params);

cleanup:

    dstu4145_free(params);
}

static void test_dstu4145_get_params(void)
{
    Dstu4145Ctx *ctx = NULL;
    int a;
    int *f = NULL;
    size_t f_len;
    ByteArray *b = NULL;
    ByteArray *n = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;

    int exp_a = DSTU4145_PARAMS_M163_PB.a;
    ByteArray *exp_b = ba_alloc_from_uint8(DSTU4145_PARAMS_M163_PB.b, sizeof(DSTU4145_PARAMS_M163_PB.b));
    const int *exp_f = DSTU4145_PARAMS_M163_PB.f;
    ByteArray *exp_n = ba_alloc_from_uint8(DSTU4145_PARAMS_M163_PB.n, sizeof(DSTU4145_PARAMS_M163_PB.n));
    ByteArray *exp_px = ba_alloc_from_uint8(DSTU4145_PARAMS_M163_PB.px, sizeof(DSTU4145_PARAMS_M163_PB.px));
    ByteArray *exp_py = ba_alloc_from_uint8(DSTU4145_PARAMS_M163_PB.py, sizeof(DSTU4145_PARAMS_M163_PB.py));

    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_RET_OK(dstu4145_get_params(ctx, &f, &f_len, &a, &b, &n, &px, &py));

    ba_change_len(b, sizeof(DSTU4145_PARAMS_M163_PB.b));
    ba_change_len(n, sizeof(DSTU4145_PARAMS_M163_PB.n));
    ba_change_len(px, sizeof(DSTU4145_PARAMS_M163_PB.px));
    ba_change_len(py, sizeof(DSTU4145_PARAMS_M163_PB.py));

    ASSERT_TRUE(exp_a == a);
    ASSERT_TRUE(! memcmp(f, exp_f, f_len));
    ASSERT_EQUALS_BA(exp_b, b);
    ASSERT_EQUALS_BA(exp_n, n);
    ASSERT_EQUALS_BA(exp_px, px);
    ASSERT_EQUALS_BA(exp_py, py);

cleanup:

    dstu4145_free(ctx);
    free(f);
    BA_FREE(b, n, px, py, exp_b, exp_n, exp_px, exp_py);
}

static void test_dstu4145_copy_with_alloc(void)
{
    ByteArray *key = ba_alloc_from_le_hex_string("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    ByteArray *qx = ba_alloc_from_le_hex_string("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
    ByteArray *qy = ba_alloc_from_le_hex_string("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
    ByteArray *hash = ba_alloc_from_le_hex_string("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    Dstu4145Ctx *ctx = NULL;
    Dstu4145Ctx *ctx_copy1 = NULL;
    Dstu4145Ctx *ctx_copy2 = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));
    ASSERT_NOT_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));

    ASSERT_RET_OK(dstu4145_init_sign(ctx, key, prng));
    ASSERT_NOT_NULL(ctx_copy1 = dstu4145_copy_with_alloc(ctx));

    ASSERT_RET_OK(dstu4145_sign(ctx, hash, &r, &s));
    ASSERT_RET_OK(dstu4145_init_verify(ctx, qx, qy));
    ASSERT_NOT_NULL(ctx_copy2 = dstu4145_copy_with_alloc(ctx));

    ASSERT_RET_OK(dstu4145_verify(ctx, hash, r, s));

    BA_FREE(r, s);

    dstu4145_free(ctx);
    ctx = NULL;

    ASSERT_RET_OK(dstu4145_sign(ctx_copy1, hash, &r, &s));
    ASSERT_RET_OK(dstu4145_verify(ctx_copy2, hash, r, s));

cleanup:

    prng_free(prng);
    dstu4145_free(ctx);
    dstu4145_free(ctx_copy1);
    dstu4145_free(ctx_copy2);
    BA_FREE(key, qx, qy, hash, r, s, seed);
}

#define UTEST_DSTU4145_SIGN_CORE(from, to, func, opt_level)            \
{                                                                      \
    size_t i = 0;                                                      \
    for (i = from; i <= to; i++) {                                     \
        func((Dstu4145ParamsId) i, opt_level);                         \
    }                                                                  \
}

#define UTEST_DSTU4145_SIGN_CORE_2(from, to, func, opt_level1, opt_level2, opt_level3)            \
{                                                                                                 \
    size_t i = 0;                                                                                 \
    for (i = from; i <= to; i++) {                                                                \
        func((Dstu4145ParamsId) i, opt_level1, opt_level2, opt_level3);                           \
    }                                                                                             \
}

void utest_dstu4145(void)
{
    PR("%s\n", __FILE__);

    dstu4145_sign_test();
    dstu4145_verify_test();
    dstu4145_verify_367_test();
    dstu4145_keys_test();
    dstu4145_dh_test();

    test_dstu4145_equals_params();
    test_dstu4145_equals_params2();
    test_dstu4145_equals_params3();

    test_dstu4145_is_onb_params();
    test_dstu4145_get_params();

    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x5505);
    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x5055);
    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x5555);
    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x5004);
    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x0204);
    test_dstu4145_set_wrong_opt_level(DSTU4145_PARAMS_ID_M257_PB, 0x0405);

    test_dstu4145_copy_with_alloc();

#ifdef UTEST_FULL
    dstu4145_onb_to_pb_173();
    dstu4145_onb_to_pb_179();
    dstu4145_onb_to_pb_431();

    dstu4145_onb_to_pb_test();
    dstu4145_pb_to_onb_test();

    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M257_PB, DSTU4145_PARAMS_ID_M431_ONB, dstu4145_sign_core,
            OPT_LEVEL_WIN_5_WIN_5);
    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M163_PB, DSTU4145_PARAMS_ID_M257_PB, dstu4145_sign_core,
            OPT_LEVEL_COMB_5_COMB_5);

    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M163_PB, DSTU4145_PARAMS_ID_M257_PB, dstu4145_sign_core_2,
            OPT_LEVEL_COMB_11_WIN_5);
    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M257_PB, DSTU4145_PARAMS_ID_M431_ONB, dstu4145_sign_core_2,
            OPT_LEVEL_WIN_11_WIN_11);

    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M257_PB, DSTU4145_PARAMS_ID_M431_ONB, dstu4145_sign_core_3,
            OPT_LEVEL_COMB_5_WIN_5);
    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M163_PB, DSTU4145_PARAMS_ID_M257_PB, dstu4145_sign_core_3,
            OPT_LEVEL_COMB_11_COMB_11);

    UTEST_DSTU4145_SIGN_CORE_2(DSTU4145_PARAMS_ID_M257_PB, DSTU4145_PARAMS_ID_M257_PB, dstu4145_sign_core_4,
            OPT_LEVEL_COMB_5_COMB_5, OPT_LEVEL_COMB_11_WIN_5, OPT_LEVEL_WIN_5_WIN_5);
    UTEST_DSTU4145_SIGN_CORE_2(DSTU4145_PARAMS_ID_M431_PB, DSTU4145_PARAMS_ID_M431_PB, dstu4145_sign_core_4,
            OPT_LEVEL_WIN_11_WIN_11, OPT_LEVEL_COMB_5_COMB_5, OPT_LEVEL_COMB_11_COMB_11);
#else
    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M257_PB, DSTU4145_PARAMS_ID_M257_PB, dstu4145_sign_core,
            OPT_LEVEL_COMB_11_WIN_5);
    UTEST_DSTU4145_SIGN_CORE(DSTU4145_PARAMS_ID_M431_PB, DSTU4145_PARAMS_ID_M431_PB, dstu4145_sign_core,
            OPT_LEVEL_COMB_11_WIN_5);
#endif
}
