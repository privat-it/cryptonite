/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "word_internal.h"
#include "math_gf2m_internal.h"

void gf2m_mod(Gf2mCtx *ctx, WordArray *a, WordArray *out);

static void gf2m_mod_test(void)
{
    WordArray *a = wa_alloc_from_be_hex_string(
            "3cb5433a00006574cdff5a65413c1f60f554678654356a123cb5433a00006574cdff5a65413c1f60");
    int f[5] = {163, 7, 6, 3, 0};
    WordArray *exp = wa_alloc_from_be_hex_string("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    WordArray *act = wa_alloc_with_zero(exp->len);
    wa_change_len(a, 2 * WA_LEN_FROM_BITS(164));

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod(ctx, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod2_test(void)
{
    int f[5] = {128, 7, 2, 1, 0};
    WordArray *a = wa_alloc_from_be_hex_string("cae7c4e764cd5150ac266b80cf45b32ee9f5810a8959efc3328993d09f6cb0");
    WordArray *exp = wa_alloc_from_be_hex_string("049eea0ac0cd193f126654f4135516d29");
    WordArray *act = wa_alloc_with_zero(exp->len);
    wa_change_len(a, 2 * WA_LEN_FROM_BITS(129));

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod(ctx, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod3_test(void)
{
    int f[5] = {257, 12, 0, 0, 0};
    WordArray *a = wa_alloc_from_be_hex_string(
            "1251274177579940e38308e7ffef65e24c18f26696c499d0deb33968d751c4b3be30ad40f7ec3fe8fb6907ca57d8bf892a37f21bbb54101eb897bca9939d0930d");
    WordArray *exp = wa_alloc_from_be_hex_string(
            "00000001e22355af08df45492efbc46d3001f18cba8bf9ed4f8da034e0566a77614e2204");
    wa_change_len(a, 2 * WA_LEN_FROM_BITS(258));
    wa_change_len(exp, WA_LEN_FROM_BITS(258));
    WordArray *act = wa_alloc_with_zero(exp->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod(ctx, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod_sqr_test(void)
{
    int f[5] = {163, 7, 6, 3, 0};
    WordArray *a = wa_alloc_from_be_hex_string("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    WordArray *exp = wa_alloc_from_be_hex_string("6d61f9ccb2fe18a17183961a09bc7823e7a1380f8");
    WordArray *act = wa_alloc_with_zero(exp->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod_sqr(ctx, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod_mul_test(void)
{
    int f[5] = {163, 7, 6, 3, 0};
    WordArray *a = wa_alloc_from_be_hex_string("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    WordArray *exp = wa_alloc_from_be_hex_string("6d61f9ccb2fe18a17183961a09bc7823e7a1380f8");
    WordArray *act = wa_alloc_with_zero(exp->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod_mul(ctx, a, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod_inv_test(void)
{
    int f[5] = {163, 7, 6, 3, 0};
    WordArray *a = wa_alloc_from_be_hex_string("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    WordArray *exp = wa_alloc_from_be_hex_string("02a4549bb5d036d6e9ccd9fa79f8742ce6774b79b");
    WordArray *act = wa_alloc_with_zero(exp->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod_inv(ctx, a, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gf2m_free(ctx);
}

static void gf2m_mod_mul_gmac_kalina_test(void)
{
    int f[5] = {128, 7, 2, 1, 0};
    WordArray *a = wa_alloc_from_le_hex_string("303132333435363738393A3B3C3D3E3F00");
    WordArray *b = wa_alloc_from_le_hex_string("C98021FE11626E6924BF8A334C526C0500");
    WordArray *exp = wa_alloc_from_le_hex_string("296D5135414F6526F193D10CACA0EE4900");
    WordArray *act = wa_alloc_with_zero(exp->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);
    gf2m_mod_mul(ctx, a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    gf2m_free(ctx);
    wa_free(a);
    wa_free(b);
    wa_free(exp);
    wa_free(act);
}

void gf2m_mul_opt(const Gf2mCtx *ctx, const WordArray *x1, const WordArray *y1, WordArray *r1);

void test_multiply_poly_0(void)
{
    int f[] = {163, 7, 6, 3, 0};

    WordArray *a = wa_alloc_from_be_hex_string("000000011dfa21231dfa21230000adfd3faa321232134231");
    WordArray *b = wa_alloc_from_be_hex_string("000000011dfa2123028617bf016569be1dfa212345453256");

    WordArray *expected =
            wa_alloc_from_le_hex_string("f671db00ff293fee65f4b240cce719e9e3b1bae942649c0ccc206195a74c36731123191a445551010100000000000000");
    WordArray *actual = wa_alloc(expected->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);

    gf2m_mul_opt(ctx, a, b, actual);

    ASSERT_EQUALS_WA(expected, actual);
    wa_free(a);
    wa_free(b);
    wa_free(expected);
    wa_free(actual);
    gf2m_free(ctx);
}

void test_multiply_poly_1(void)
{
    int f[3] = {257, 12, 0};

    WordArray *a = wa_alloc_from_be_hex_string("000000011dfa21230000adfd454532561dfa21231dfa21230000adfd3faa321232134231");
    WordArray *b = wa_alloc_from_be_hex_string("00000001000008ed000009270000b0b20004ef60028617bf016569be1dfa212345453256");

    WordArray *expected =
            wa_alloc_from_be_hex_string("0000000000000000000000011dfa292b6816edbc85cfd76f401642958e07ae69bbe7ab98d0e30707386a0e988ad9aa5cce712e5025edd44cba8815f0e919e7cc40b2f465ee3f29ff00db71f6");
    wa_change_len(expected, a->len * 2);
    WordArray *actual = wa_alloc(expected->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 3);

    gf2m_mul_opt(ctx, a, b, actual);

    ASSERT_EQUALS_WA(expected, actual);

    ASSERT_EQUALS_WA(expected, actual);
    wa_free(a);
    wa_free(b);
    wa_free(expected);
    wa_free(actual);
    gf2m_free(ctx);
}

void test_mul_poly_431(void)
{
    int f[5] = { 431, 5, 3, 1, 0 };

    WordArray *a =
            wa_alloc_from_be_hex_string("1dfa21230000adfd1dfa21230000adfd3faa3212321342311dfa21230000adfd454532561dfa21231dfa21230000adfd3faa321232134231");
    WordArray *b =
            wa_alloc_from_be_hex_string("000008ed000009271dfa21230000adfd3faa3212321342311dfa21230000adfd454532561dfa2123028617bf016569be1dfa212345453256");

    WordArray *expected =
            wa_alloc_from_be_hex_string("000000e568164966c1db0ea969c3a630c3084a5449523caae86e8acff4e95e08c2cc91743064664945abf07f3a5b64a613c12b13cb157704d0e9df3595c75d83fd39a21132d4249f3c7d339b943b35c8bd168880e9cda0497e1574c7e9bab1e3e919e7cc40b2f465ee3f29ff00db71f6");
    WordArray *actual = wa_alloc(expected->len);

    Gf2mCtx *ctx = gf2m_alloc(f, 5);

    gf2m_mul_opt(ctx, a, b, actual);

    ASSERT_EQUALS_WA(expected, actual);

    ASSERT_EQUALS_WA(expected, actual);
    wa_free(a);
    wa_free(b);
    wa_free(expected);
    wa_free(actual);
    gf2m_free(ctx);
}

void utest_math_gf2m(void)
{
    PR("%s\n", __FILE__);

    gf2m_mod_test();
    gf2m_mod2_test();
    gf2m_mod3_test();
    gf2m_mod_sqr_test();
    gf2m_mod_mul_test();
    gf2m_mod_inv_test();
    gf2m_mod_mul_gmac_kalina_test();

    test_multiply_poly_0();
    test_multiply_poly_1();
    test_mul_poly_431();
}
