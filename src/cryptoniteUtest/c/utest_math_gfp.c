/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "word_internal.h"
#include "math_gfp_internal.h"
#include "math_int_internal.h"

static void gfp_mod_add_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("b937eea5a571f05bf75e006a914d0a009408bf7a2e13811dff44970e50dd9166");
    WordArray *b = wa_alloc_from_be_hex_string("5bafd9df34ee8ab252a789dc4ba99bd10257f7ee68c409180b5911a7640a9265");
    WordArray *exp = wa_alloc_from_le_hex_string("9a1fe8b4b5a89d0a368ad79668b76096d1a5f6dc468a054a0e7b60da84c8e794");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_add(ctx, a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(b);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_sub_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("8d1c80700b9c893f15c1133c08b8f8d5c8957e343b3ba28c1a81280aedb6b96b");
    WordArray *b = wa_alloc_from_be_hex_string("1e6c0cb9cfd9090f5e38d06387bb6774aa5a4c6cbb190c2be94ae94f19e55948");
    WordArray *exp = wa_alloc_from_le_hex_string("2360d1d3bb3e363160962280c7313b1e6191fd80d84288b72f80c33bb673b06e");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_sub(ctx, a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(b);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_mul_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("fcafb4c6ad8aad4e067ceae2e411a9f2be9fab116ff4425a98dc370beabf7b22");
    WordArray *b = wa_alloc_from_be_hex_string("ce63ae62f3fd855d694ed83577af18dd2d966db5d494dec0d571e3ec3ffa6f51");
    WordArray *exp = wa_alloc_from_le_hex_string("b330c4546d209fb683f305472486a130cd93ff897122ab79c6ef63635b44857a");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_mul(ctx, a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(b);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_pow_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("7b1e6b7b3c985ff4d0fc90e1195b2fdc5bc96f9fdddb7b394743bcf380e65050");
    WordArray *x = wa_alloc_from_be_hex_string("174a521f4f14693c2b10404b8e61d6353b7a129cd299428fcf9d5bc58484d77f");
    WordArray *exp = wa_alloc_from_le_hex_string("2d42390cb99bc74966c3fbb316e7b57f04d7e0a6f1ff359341dd64adb1e57776");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_pow(ctx, a, x, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(x);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_dual_pow_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("2b72116c655f296402d37b50362ce3884ba7340d5f0567cf2abde64ca449641d");
    WordArray *b = wa_alloc_from_be_hex_string("1e6c0cb9cfd9090f5e38d06387bb6774aa5a4c6cbb190c2be94ae94f19e55948");
    WordArray *x = wa_alloc_from_be_hex_string("fa773f0eab0384555e5bb64064825c86f5b6a748197e56d115810be82cbdd071");
    WordArray *y = wa_alloc_from_be_hex_string("88ca0ddacecadb17357d5e52a2f3793e908e9d364ffe208e4473cd8839958c38");
    WordArray *exp = wa_alloc_from_le_hex_string("701ba8804c600150112e01cd3243e21d223644681d8fef984c33ef8873bee059");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_dual_pow(ctx, a, x, b, y, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(b);
    wa_free(x);
    wa_free(y);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_inv_test(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("f8811c92b8e561e8ad129635c42bbab41529b0b2b6ff41fe61834e85d7ed3139");
    WordArray *exp = wa_alloc_from_le_hex_string("c8d4263cafe677ec48ca08d33b78371c90d30385c59a296a75cc59c1d0fc505c");
    WordArray *act = NULL;
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    act = gfp_mod_inv(ctx, a);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

static void gfp_mod_inv_test_new(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("67d8d1d5b4f6d96447332024abddce304f914e79387985c7ce3b09942264b265");
    WordArray *exp = wa_alloc_from_le_hex_string("716b456fa2bc3634699b17e20b97dc928f702037b0b699cc2ac872edec7e6675");
    WordArray *act = NULL;

    act = gfp_mod_inv_core(a, p);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(exp);
    wa_free(act);
}

static void gfp_mod_inv_test2(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("001374E0");
    WordArray *a = wa_alloc_from_be_hex_string("00000017");
    WordArray *exp = wa_alloc_from_be_hex_string("000aff47");
    WordArray *act = NULL;

    act = gfp_mod_inv_core(a, p);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(exp);
    wa_free(act);
}

static void gfp_mod_pow_test2(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("f2ebf2d602a5381dadd8972654a70fc16d6adface6f266f39a9bd9fbcd628d5e"
                                               "2ae8db4851efda684d1dc99dd1a365a47c59383126c07d0d9334e914d1249706");
    WordArray *a = wa_alloc_from_be_hex_string("8fadc78c5350711d75af57628b9308df6e1b2a87a25cf36266e7921a7a189335"
                                               "0255bbd508fd7d0b0c81c601bff778e30ec9328317dd0ffddde9bb0c7e16d70f");
    WordArray *x = wa_alloc_from_be_hex_string("734b027a43d2251a55fe7e903b76849baa822e48fddac927a99bdedde9e47265"
                                               "05cfdafbde4d66915d87791b2e7d19a516020c390fe1663ab9e0e0fbd7578f9e");
    WordArray *exp = wa_alloc_from_le_hex_string("ff852686dd44cda047652e85ed60dee0ad27f365712e441e17ebab77035e1c49"
                                                 "384cff565e7a6606d749c639a897dd2ed3a41e490dcb601e116817eacc4ea99a");
    WordArray *act = wa_alloc_with_zero(p->len);
    GfpCtx *ctx = NULL;

    ctx = gfp_alloc(p);
    gfp_mod_pow(ctx, a, x, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(p);
    wa_free(a);
    wa_free(x);
    wa_free(exp);
    wa_free(act);
    gfp_free(ctx);
}

void utest_math_gfp(void)
{
    PR("%s\n", __FILE__);

    gfp_mod_add_test();
    gfp_mod_sub_test();
    gfp_mod_mul_test();
    gfp_mod_inv_test();
    gfp_mod_pow_test();
    gfp_mod_pow_test2();
    gfp_mod_dual_pow_test();
    gfp_mod_inv_test_new();
    gfp_mod_inv_test2();
}
