/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "byte_utils_internal.h"
#include "math_int_internal.h"
#include "dsa.h"
#include "rs.h"

#ifdef FULL_UTEST
static void test_dsa_generate_params(int l, int n)
{
    ByteArray *p = NULL;
    ByteArray *q = NULL;
    ByteArray *g = NULL;
    WordArray *one = NULL;
    WordArray *wq = NULL;
    WordArray *wp = NULL;
    DsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    bool is_prime;

    ASSERT_NOT_NULL(seed = ba_alloc_by_len(128));
    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    ASSERT_NOT_NULL(ctx = dsa_alloc_ext(l, n, prng));
    ASSERT_TRUE(ctx != NULL);
    ASSERT_RET_OK(dsa_get_params(ctx, &p, &q, &g));

    wp = wa_alloc_from_ba(p);
    wq = wa_alloc_from_ba(q);

    ASSERT_NOT_NULL(wp);
    ASSERT_NOT_NULL(wq);

    int_is_prime(wp, &is_prime);
    ASSERT_TRUE(is_prime);
    int_is_prime(wq, &is_prime);
    ASSERT_TRUE(is_prime);
    ASSERT_EQUALS_SIZE_T(int_bit_len(wp), l);
    ASSERT_EQUALS_SIZE_T(int_bit_len(wq), n);

    wa_change_len(wq, wp->len / 2);
    one = wa_alloc(wp->len / 2);
    int_div(wp, wq, NULL, one);
    ASSERT_TRUE(int_is_one(one));

cleanup:

    wa_free(wp);
    wa_free(wq);
    wa_free(one);
    dsa_free(ctx);
    prng_free(prng);

    BA_FREE(p, q, g, seed);
}
#endif
static void test_dsa_get_pubkey(void)
{
    ByteArray *p = ba_alloc_from_be_hex_string(
            "a65feaab511c61e33df38fdddaf03b59b6f25e1fa4de57e5cf00ae478a855dda4f3638d38bb00ac4af7d8414c3fb36e04fbdf3d3166712d43b421bfa757e85694ad27c48f396d03c8bce8da58db5b82039f35dcf857235c2f1c73b2226a361429190dcb5b6cd0edfb0ff6933900b02cecc0ce69274d8dae7c694804318d6d6b9");
    ByteArray *q = ba_alloc_from_be_hex_string("000000000000000000000000b5afd2f93246b1efcd1f3a7c240c1e9e21a3630b");
    ByteArray *g = ba_alloc_from_be_hex_string(
            "007bbd2c5dc917a5e08b9c2f80a49fb63fcd5c0578ba701e254fe3530dedd3b6680a6e5afb3280b53f154028bafff73d1ba0fdb0004b9eb0dbf24b295bf2a356913cd1c0be03c5103a1da8b73e7670b56d716ed5547af67b5061311eea245e2e5c337843cbc135b9b9c18775d5d56cfda31b747e2449861adf3b3f727189c0a3");
    ByteArray *priv_key = ba_alloc_from_be_hex_string(
            "0000000000000000000000002070b3223dba372fde1c0ffc7b2e3b498b260614");
    ByteArray *pub_key = ba_alloc_from_be_hex_string(
            "87c9b20aaef34afcbd6ffb5509e7cb3b43f8bec56ba74ad089d2ac2659b9fa8f895d51b59891f0a5afe8b2e11ae133ac16529ffc031eedf7834f6c1bce2604c4e5cc750df577d29c08f0a6e4f7e190d21b683fb6e08f4d9ea6ea1f03d7720cea0a97c03969118dea97d3efc30d0dcd80495cf2ea84eac1b44fb3d2b8e25e0bd8");
    ByteArray *pub_key_act = NULL;
    DsaCtx *ctx = NULL;

    ctx = dsa_alloc(p, q, g);
    ASSERT_RET_OK(dsa_get_pubkey(ctx, priv_key, &pub_key_act));

    ASSERT_EQUALS_BA(pub_key, pub_key_act);

cleanup:

    dsa_free(ctx);
    BA_FREE(p, q, g, priv_key, pub_key, pub_key_act);
}

static void test_dsa_sign_verify(void)
{
    ByteArray *p = ba_alloc_from_be_hex_string(
            "a65feaab511c61e33df38fdddaf03b59b6f25e1fa4de57e5cf00ae478a855dda4f3638d38bb00ac4af7d8414c3fb36e04fbdf3d3166712d43b421bfa757e85694ad27c48f396d03c8bce8da58db5b82039f35dcf857235c2f1c73b2226a361429190dcb5b6cd0edfb0ff6933900b02cecc0ce69274d8dae7c694804318d6d6b9");
    ByteArray *q = ba_alloc_from_be_hex_string("000000000000000000000000b5afd2f93246b1efcd1f3a7c240c1e9e21a3630b");
    ByteArray *g = ba_alloc_from_be_hex_string(
            "007bbd2c5dc917a5e08b9c2f80a49fb63fcd5c0578ba701e254fe3530dedd3b6680a6e5afb3280b53f154028bafff73d1ba0fdb0004b9eb0dbf24b295bf2a356913cd1c0be03c5103a1da8b73e7670b56d716ed5547af67b5061311eea245e2e5c337843cbc135b9b9c18775d5d56cfda31b747e2449861adf3b3f727189c0a3");
    ByteArray *priv_key = ba_alloc_from_be_hex_string(
            "0000000000000000000000002070b3223dba372fde1c0ffc7b2e3b498b260614");
    ByteArray *pub_key = ba_alloc_from_be_hex_string(
            "87c9b20aaef34afcbd6ffb5509e7cb3b43f8bec56ba74ad089d2ac2659b9fa8f895d51b59891f0a5afe8b2e11ae133ac16529ffc031eedf7834f6c1bce2604c4e5cc750df577d29c08f0a6e4f7e190d21b683fb6e08f4d9ea6ea1f03d7720cea0a97c03969118dea97d3efc30d0dcd80495cf2ea84eac1b44fb3d2b8e25e0bd8");
    ByteArray *hash = ba_alloc_from_be_hex_string("a9993e364706816aba3e25717850c26c9cd0d89d");
    ByteArray *pub_key_act = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    DsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(128);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);
    ctx = dsa_alloc(p, q, g);

    ASSERT_RET_OK(dsa_get_pubkey(ctx, priv_key, &pub_key_act));
    ASSERT_EQUALS_BA(pub_key, pub_key_act);

    ASSERT_RET_OK(dsa_init_sign(ctx, priv_key, prng));
    ASSERT_RET_OK(dsa_sign(ctx, hash, &r, &s));

    ASSERT_RET_OK(dsa_init_verify(ctx, pub_key));
    ASSERT_RET_OK(dsa_verify(ctx, hash, r, s));

cleanup:

    prng_free(prng);
    dsa_free(ctx);
    BA_FREE(p, q, g, priv_key, pub_key, pub_key_act, hash, r, s, seed);
}

static void test_dsa_alloc_ext_l_is_not_correct(void)
{
    DsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(128);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    ctx = dsa_alloc_ext(256, 160, prng);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:

    prng_free(prng);
    dsa_free(ctx);
    ba_free(seed);
}

static void test_dsa_alloc_ext_n_is_not_correct(void)
{
    DsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(128);

    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    ctx = dsa_alloc_ext(512, 128, prng);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:

    prng_free(prng);
    dsa_free(ctx);
    ba_free(seed);
}

void utest_dsa(void)
{
    PR("%s\n", __FILE__);
#ifdef FULL_UTEST
    test_dsa_generate_params(1024, 160);
#endif
    test_dsa_get_pubkey();
    test_dsa_sign_verify();
    test_dsa_alloc_ext_l_is_not_correct();
    test_dsa_alloc_ext_n_is_not_correct();
}
