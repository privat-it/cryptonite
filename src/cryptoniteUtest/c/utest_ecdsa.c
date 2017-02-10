/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "byte_array_internal.h"
#include "word_internal.h"
#include "sha1.h"
#include "ecdsa.h"
#include "ecdsa_params_internal.h"

static const EcdsaDefaultParamsCtx ECDSA_PARAMS_SEC_P192_R1 = {
    24,
    {
        0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    },
    {
        0xb1, 0xb9, 0x46, 0xc1, 0xec, 0xde, 0xb8, 0xfe, 0x49, 0x30, 0x24, 0x72, 0xab, 0xe9, 0xa7, 0x0f,
        0xe7, 0x80, 0x9c, 0xe5, 0x19, 0x05, 0x21, 0x64
    },
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    },
    {
        0x31, 0x28, 0xd2, 0xb4, 0xb1, 0xc9, 0x6b, 0x14, 0x36, 0xf8, 0xde, 0x99, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    },
    {
        0x12, 0x10, 0xff, 0x82, 0xfd, 0x0a, 0xff, 0xf4, 0x00, 0x88, 0xa1, 0x43, 0xeb, 0x20, 0xbf, 0x7c,
        0xf6, 0x90, 0x30, 0xb0, 0x0e, 0xa8, 0x8d, 0x18
    },
    {
        0x11, 0x48, 0x79, 0x1e, 0xa1, 0x77, 0xf9, 0x73, 0xd5, 0xcd, 0x24, 0x6b, 0xed, 0x11, 0x10, 0x63,
        0x78, 0xda, 0xc8, 0xff, 0x95, 0x2b, 0x19, 0x07
    }
};

static void test_ecdsa_verify(void)
{
    EcdsaCtx *ctx = NULL;
    ByteArray *qx = ba_alloc_from_be_hex_string("07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6");
    ByteArray *qy = ba_alloc_from_be_hex_string("76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477");
    ByteArray *hash = ba_alloc_from_le_hex_string("608079423f12421de616b7493ebe551cf4d65b92");
    ByteArray *r = ba_alloc_from_be_hex_string("6994d962bdd0d793ffddf855ec5bf2f91a9698b46258a63e");
    ByteArray *s = ba_alloc_from_be_hex_string("02ba6465a234903744ab02bc8521405b73cf5fc00e1a9f41");

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1);

    ASSERT_RET_OK(ecdsa_set_opt_level(ctx, OPT_LEVEL_COMB_5_WIN_5));

    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));

cleanup:

    ecdsa_free(ctx);
    BA_FREE(qx, qy, hash, r, s);
}

static void test_ecdsa_keys(void)
{
    EcdsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *key = ba_alloc_from_be_hex_string("e14f37b3d1374ff8b03f41b9b3fdd2f0ebccf275d660d7f3");
    ByteArray *qx = ba_alloc_from_be_hex_string("07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6");
    ByteArray *qy = ba_alloc_from_be_hex_string("76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477");
    ByteArray *d = NULL;
    ByteArray *qx_act = NULL;
    ByteArray *qy_act = NULL;

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1);

    prng = test_utils_get_prng();

    ASSERT_RET_OK(ecdsa_generate_privkey(ctx, prng, &d));

    ASSERT_RET_OK(ecdsa_get_pubkey(ctx, key, &qx_act, &qy_act));
    ASSERT_EQUALS_BA(qx, qx_act);
    ASSERT_EQUALS_BA(qy, qy_act);

cleanup:

    ecdsa_free(ctx);
    prng_free(prng);
    BA_FREE(d, key, qx, qy, qx_act, qy_act);
}

static void test_compress_decompress_key_192(void)
{
    EcdsaCtx *ctx = NULL;
    ByteArray *qx = ba_alloc_from_be_hex_string("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
    ByteArray *qy = ba_alloc_from_be_hex_string("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
    ByteArray *q = ba_alloc_from_be_hex_string("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
    int last_qy_bit = 1;
    ByteArray *q_act = NULL;
    ByteArray *qx_act = NULL;
    ByteArray *qy_act = NULL;
    int last_qy_bit_act = 1;

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1);

    ASSERT_RET_OK(ecdsa_compress_pubkey(ctx, qx, qy, &q_act, &last_qy_bit_act));
    ASSERT_EQUALS_BA(q, q_act);
    ASSERT_EQUALS(&last_qy_bit, &last_qy_bit_act, sizeof(int));

    ASSERT_RET_OK(ecdsa_decompress_pubkey(ctx, q, last_qy_bit, &qx_act, &qy_act));
    ASSERT_EQUALS_BA(qx, qx_act);
    ASSERT_EQUALS_BA(qy, qy_act);

cleanup:

    ecdsa_free(ctx);
    BA_FREE(qx, qy, q, qx_act, qy_act, q_act);
}

static void test_compress_decompress_key_224(void)
{
    EcdsaCtx *ctx = NULL;
    ByteArray *qx = ba_alloc_from_be_hex_string("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21");
    ByteArray *qy = ba_alloc_from_be_hex_string("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
    ByteArray *q = ba_alloc_from_be_hex_string("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21");
    int last_qy_bit = 0;
    ByteArray *q_act = NULL;
    ByteArray *qx_act = NULL;
    ByteArray *qy_act = NULL;
    int last_qy_bit_act = 1;

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P224_R1);

    ASSERT_RET_OK(ecdsa_compress_pubkey(ctx, qx, qy, &q_act, &last_qy_bit_act));
    ASSERT_EQUALS_BA(q, q_act);
    ASSERT_EQUALS(&last_qy_bit, &last_qy_bit_act, sizeof(int));

    ASSERT_RET_OK(ecdsa_decompress_pubkey(ctx, q, last_qy_bit, &qx_act, &qy_act));
    ASSERT_EQUALS_BA(qx, qx_act);
    ASSERT_EQUALS_BA(qy, qy_act);

cleanup:

    ecdsa_free(ctx);
    BA_FREE(qx, qy, q, qx_act, qy_act, q_act);
}

static void test_ecdsa_sign(void)
{
    ByteArray *key = ba_alloc_from_be_hex_string("e14f37b3d1374ff8b03f41b9b3fdd2f0ebccf275d660d7f3");
    ByteArray *qx = ba_alloc_from_be_hex_string("07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6");
    ByteArray *qy = ba_alloc_from_be_hex_string("76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477");
    ByteArray *hash = ba_alloc_from_le_hex_string("608079423f12421de616b7493ebe551cf4d65b92");
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    EcdsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1);

    ASSERT_RET_OK(ecdsa_init_sign(ctx, key, prng));
    ASSERT_RET_OK(ecdsa_sign(ctx, hash, &r, &s));

    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));

cleanup:

    prng_free(prng);
    ecdsa_free(ctx);
    BA_FREE(key, qx, qy, hash, r, s);
}

static void test_ecdsa_get_params(void)
{
    EcdsaCtx *ctx = NULL;
    ByteArray *a = NULL;
    ByteArray *b = NULL;
    ByteArray *p = NULL;
    ByteArray *q = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    ByteArray *exp_a = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.a, ECDSA_PARAMS_SEC_P192_R1.len);
    ByteArray *exp_b = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.b, ECDSA_PARAMS_SEC_P192_R1.len);
    ByteArray *exp_p = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.p, ECDSA_PARAMS_SEC_P192_R1.len);
    ByteArray *exp_q = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.q, ECDSA_PARAMS_SEC_P192_R1.len);
    ByteArray *exp_px = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.px, ECDSA_PARAMS_SEC_P192_R1.len);
    ByteArray *exp_py = ba_alloc_from_uint8(ECDSA_PARAMS_SEC_P192_R1.py, ECDSA_PARAMS_SEC_P192_R1.len);
    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_RET_OK(ecdsa_get_params(ctx, &p, &a, &b, &q, &px, &py));
    ASSERT_EQUALS_BA(exp_a, a);
    ASSERT_EQUALS_BA(exp_b, b);
    ASSERT_EQUALS_BA(exp_p, p);
    ASSERT_EQUALS_BA(exp_q, q);
    ASSERT_EQUALS_BA(exp_px, px);
    ASSERT_EQUALS_BA(exp_py, py);

cleanup:

    ecdsa_free(ctx);
    BA_FREE(a, b, p, q, px, py, exp_a, exp_b, exp_p, exp_q, exp_px, exp_py);
}

static void test_ecdsa_equals_params(void)
{
    EcdsaCtx *param_a = NULL;
    EcdsaCtx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_NOT_NULL(param_b = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_RET_OK(ecdsa_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(equals);

cleanup:

    ecdsa_free(param_a);
    ecdsa_free(param_b);
}

static void test_ecdsa_equals_params_2(void)
{
    EcdsaCtx *param_a = NULL;
    EcdsaCtx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P224_R1));
    ASSERT_NOT_NULL(param_b = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P521_R1));
    ASSERT_RET_OK(ecdsa_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(!equals);

cleanup:

    ecdsa_free(param_a);
    ecdsa_free(param_b);
}

static void test_ecdsa_equals_params_3(void)
{
    EcdsaCtx *param_a = NULL;
    EcdsaCtx *param_b = NULL;
    bool equals;
    ASSERT_NOT_NULL(param_a = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P224_R1));
    ASSERT_NOT_NULL(param_b = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P256_R1));
    ASSERT_RET_OK(ecdsa_equals_params(param_a, param_b, &equals));
    ASSERT_TRUE(!equals);

cleanup:

    ecdsa_free(param_a);
    ecdsa_free(param_b);
}

static void test_ecdsa_copy_with_alloc(void)
{
    ByteArray *key = ba_alloc_from_be_hex_string("e14f37b3d1374ff8b03f41b9b3fdd2f0ebccf275d660d7f3");
    ByteArray *qx = ba_alloc_from_be_hex_string("07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6");
    ByteArray *qy = ba_alloc_from_be_hex_string("76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477");
    ByteArray *hash = ba_alloc_from_le_hex_string("608079423f12421de616b7493ebe551cf4d65b92");
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    PrngCtx *prng = test_utils_get_prng();
    EcdsaCtx *ctx = NULL;
    EcdsaCtx *ctx_copy1 = NULL;
    EcdsaCtx *ctx_copy2 = NULL;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));

    ASSERT_RET_OK(ecdsa_init_sign(ctx, key, prng));
    ASSERT_NOT_NULL(ctx_copy1 = ecdsa_copy_with_alloc(ctx));

    ASSERT_RET_OK(ecdsa_sign(ctx, hash, &r, &s));
    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    ASSERT_NOT_NULL(ctx_copy2 = ecdsa_copy_with_alloc(ctx));

    ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));

    BA_FREE(r, s);

    ecdsa_free(ctx);
    ctx = NULL;

    ASSERT_RET_OK(ecdsa_sign(ctx_copy1, hash, &r, &s));
    ASSERT_RET_OK(ecdsa_verify(ctx_copy2, hash, r, s));

cleanup:

    prng_free(prng);
    ecdsa_free(ctx);
    ecdsa_free(ctx_copy1);
    ecdsa_free(ctx_copy2);
    BA_FREE(key, qx, qy, hash, r, s);
}

#ifdef FULL_UTEST
static void ecdsa_all(EcdsaCtx *ctx, const ByteArray *hash)
{
    ByteArray *key = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *qx2 = NULL;
    ByteArray *qy2 = NULL;
    ByteArray *q = NULL;
    int last_qy_bit;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_RET_OK(ecdsa_generate_privkey(ctx, prng, &key));
    ASSERT_RET_OK(ecdsa_init_sign(ctx, key, prng));
    ASSERT_RET_OK(ecdsa_sign(ctx, hash, &r, &s));

    ASSERT_RET_OK(ecdsa_get_pubkey(ctx, key, &qx, &qy));
    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));

    ASSERT_RET_OK(ecdsa_compress_pubkey(ctx, qx, qy, &q, &last_qy_bit));
    ASSERT_RET_OK(ecdsa_decompress_pubkey(ctx, q, last_qy_bit, &qx2, &qy2));
    ASSERT_EQUALS_BA(qx, qx2);
    ASSERT_EQUALS_BA(qy, qy2);

cleanup:

    prng_free(prng);
    BA_FREE(key, qx, qy, qx2, qy2, q, r, s);
}


static void test_ecdsa_params(void)
{
    EcdsaCtx *ctx = NULL;
    ByteArray *hash = ba_from_be_hex_string("608079423f12421de616b7493ebe551cf4d65b92");
    int i;

    for (i = ECDSA_PARAMS_ID_SEC_P192_R1; i <= ECDSA_PARAMS_ID_SEC_P521_R1; i++) {
        ctx = ecdsa_alloc(i);
        ecdsa_all(ctx, hash);
        ecdsa_free(ctx);
    }

    ba_free(hash);
}
#endif
void utest_ecdsa(void)
{
    PR("%s\n", __FILE__);

    test_ecdsa_sign();
    test_ecdsa_verify();
    test_ecdsa_keys();
    test_ecdsa_get_params();
    test_ecdsa_equals_params();
    test_ecdsa_equals_params_2();
    test_ecdsa_equals_params_3();
    test_compress_decompress_key_192();
    test_compress_decompress_key_224();
    test_ecdsa_copy_with_alloc();
#ifdef FULL_UTEST
    test_ecdsa_params();
#endif
}
