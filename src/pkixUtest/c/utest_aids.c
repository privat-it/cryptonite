/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "aid.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "oids.h"
#include "pkix_errors.h"

static AlgorithmIdentifier_t *load_test_data(void)
{
    ByteArray *oid = ba_alloc_from_le_hex_string("300D060B2A86240201010101030101");
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_NOT_NULL(aid = aid_alloc());
    ASSERT_RET_OK(aid_decode(aid, oid));
cleanup:
    BA_FREE(oid);
    return aid;
}

static void test_encode(AlgorithmIdentifier_t *aid)
{
    ByteArray *expected = ba_alloc_from_le_hex_string("300D060B2A86240201010101030101");
    ByteArray *actual = NULL;

    ASSERT_RET_OK(aid_encode(aid, &actual));
    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
}

static void test_init_by_oid(AlgorithmIdentifier_t *aid)
{
    AlgorithmIdentifier_t *aid_temp = NULL;

    ASSERT_NOT_NULL(aid_temp = aid_alloc());
    ASSERT_RET_OK(aid_init_by_oid(aid_temp, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_LE_ID)));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, &aid->algorithm, &aid_temp->algorithm);

cleanup:

    aid_free(aid_temp);
}

static void test_create_gost3411(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    AlgorithmIdentifier_t *aid_exp = NULL;

    ASSERT_NOT_NULL(aid_exp = aid_alloc());
    ASSERT_RET_OK(aid_init_by_oid(aid_exp, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID)));

    ASSERT_RET_OK(aid_create_gost3411(&aid_act));

    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, &aid_exp->algorithm, &aid_act->algorithm);

cleanup:

    aid_free(aid_act);
    aid_free(aid_exp);
}

static void test_create_gost3411_with_null(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    AlgorithmIdentifier_t *aid_exp = NULL;

    ASSERT_NOT_NULL(aid_exp = aid_alloc());
    ASSERT_RET_OK(aid_init_by_oid(aid_exp, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID)));

    ASSERT_RET_OK(aid_create_gost3411_with_null(&aid_act));

    ASSERT_EQUALS_ASN(&NULL_desc, &aid_exp->algorithm, &aid_act->algorithm);

cleanup:
    aid_free(aid_act);
    aid_free(aid_exp);
}

static void test_create_gost28147_wrap(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    AlgorithmIdentifier_t *aid_exp = NULL;

    ASSERT_NOT_NULL(aid_exp = aid_alloc());
    ASSERT_RET_OK(aid_init_by_oid(aid_exp, oids_get_oid_numbers_by_id(OID_GOST28147_WRAP_ID)));

    ASSERT_RET_OK(aid_create_gost28147_wrap(&aid_act));

    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, &aid_exp->algorithm, &aid_act->algorithm);

cleanup:
    aid_free(aid_act);
    aid_free(aid_exp);
}

static void test_aid_create_dstu4145_M163_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102000440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M167_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102010440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M167_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M173_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102020440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M179_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102030440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M191_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102040440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M191_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M233_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102050440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M233_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M257_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102060440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));
    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M307_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102070440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M307_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M367_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102080440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M367_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M431_PB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3062060d2a8624020101010103010101013051060d2a8624020101010103010102090440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_PB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, false, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

#if defined(UTEST_FULL)

static void test_aid_create_dstu4145_M173_ONB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301023051060d2a8624020101010103010202000440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M179_ONB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301023051060d2a8624020101010103010202010440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_ONB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M191_ONB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301023051060d2a8624020101010103010202020440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M191_ONB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M233_ONB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301023051060d2a8624020101010103010202030440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M233_ONB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

static void test_aid_create_dstu4145_M431_ONB(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3062060d2a8624020101010103010201013051060d2a8624020101010103010202040440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, false, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected);
}

#endif

static void test_aid_create_dstu4145_pb(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *b = ba_alloc_from_be_hex_string("5ff6108462a2dc8210ab403925e638a19c1455d21");
    ByteArray *px = ba_alloc_from_be_hex_string("72d867f93a93ac27df9ff01affe74885c8c540420");
    ByteArray *py = ba_alloc_from_be_hex_string("0224a9c3947852b97c5599d5f4ab81122adc3fd9b");
    ByteArray *n = ba_alloc_from_be_hex_string("400000000000000000002bec12be2262d39bcf14d");
    ByteArray *expected =
            ba_alloc_from_le_hex_string("3081af060d2a86240201010101030101010130819d3059300f020200a33009020103020106020107020101041505ff6108462a2dc8210ab403925e638a19c1455d2102150400000000000000000002bec12be2262d39bcf14d0415072d867f93a93ac27df9ff01affe74885c8c5404200440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");
    int a = 1;
    int f[5] = {163, 7, 6, 3, 0};

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc_pb(f, sizeof(f) / sizeof(f[0]), a, b, n, px, py));
    ASSERT_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));

    ASSERT_RET_OK(aid_create_dstu4145(dstu_ctx, gost_ctx, false, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);
    BA_FREE(encoded, expected, b, px, py, n);
}

static AlgorithmIdentifier_t *test_aid_from_hex(const char *hex)
{
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *encode = NULL;

    ASSERT_NOT_NULL(encode = ba_alloc_from_le_hex_string(hex));

    ASSERT_NOT_NULL(aid = aid_alloc());
    ASSERT_RET_OK(aid_decode(aid, encode));

cleanup:

    BA_FREE(encode);

    return aid;
}

static void test_aid_get_dstu4145_params_M163_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081AD060B2A8624020101010103010130819D3059300F020200A330090201030201060201070201010415215"
                    "D45C1198A635E9203B40A21C82D2A460861FF0502150400000000000000000002BEC12BE2262D39BCF14D0415"
                    "BE2358F3A3F8DA297223C4A583E94CD75D5FF8E2020440A9D6EB45F13C708280C4967B231F5EADF658EBA4C03"
                    "7291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M163_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M167_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081A5060B2A8624020101010103010130819530513007020200A70201060201010415AC7D825A31A4F130098"
                    "A51209F75110823EBCEE36E02153FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F041554CD218B01A2B230"
                    "3D0A91032819686A7853661F7A0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025C"
                    "A4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M167_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M173_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081B0060B2A862402010101010301013081A0305C300F020200AD300902010102010202010A0201000416D937"
                    "B46F6B8F27BB3B85F6DD6EC12FDB9904C876851002160800000000000000000000189B4E67606E3825BB283104"
                    "16CA8973D381917A56AD2FA28F44F0AD6ECC9B611AD4040440A9D6EB45F13C708280C4967B231F5EADF658EBA4"
                    "C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M179_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081B3060B2A862402010101010301013081A3305F300F020200B33009020101020102020104020101041710B7"
                    "BE724518042DE341A307DD882F6F43266585E0A604021703FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236"
                    "EF0417027D2C02674695A99B81487FC56DD22B4B4651FE06BA060440A9D6EB45F13C708280C4967B231F5EADF6"
                    "58EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC5"
                    "7904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M191_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081AE060B2A8624020101010103010130819E305A3007020200BF020109020101041803FCFE502748E027FF81"
                    "496B8B0E89D5C42E9002216EC87B021840000000000000000000000069A779CAC1DABC6788F7474F04182871EB"
                    "DA76FEFCC2B5B958ACD2A612794AFFF262B71441710440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037"
                    "291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M191_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M233_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081C8060B2A862402010101010301013081B83074300F020200E93009020101020104020109020101041E2C4D"
                    "45CE6E93AA26038A3BDDF54ED51BA2647ECFC73455679550B1736900021E010000000000000000000000000000"
                    "13E974E72F8A6922031D2603CFE0D7041E96FE5EB2EE03D02827F345351D76313C5BF38D11A13BF8CDB626A5CD"
                    "3F000440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28"
                    "975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M233_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M257_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081C9060B2A862402010101010301013081B9307530070202010102010C020100042110BEE3DB6AEA9E1F8657"
                    "8C45C12594FF942394A7D738F9187E6515017294F4CE0102210080000000000000000000000000000000675921"
                    "3AF182E987D3E17714907D470D0421B60FD2D8DCE8A93423C6101BCA91C47A007E6C300B26CD556C9B0E7D20EF"
                    "292A000440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A"
                    "28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M307_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081E4060B2A862402010101010301013081D430818F300F0202013330090201020201040201080201010427BB"
                    "6849908601C9BD90608BF10D0541E2E2E299C5C096424FE93D6D6C5E4B05B56636D5F7C79303022703FFFFFFFF"
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B70427AA32726E2DC0523C74"
                    "67316D279B237A085A82CD5CF76BD1F1921E4C9824021A299D188BEE16020440A9D6EB45F13C708280C4967B23"
                    "1F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E"
                    "6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M307_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M367_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081F1060B2A862402010101010301013081E130819C30070202016F020115020101042E365199567B435597A7"
                    "794C39923DF9B8DACA42FE2A0C4BA6A46ABF476B55474465D57A62D1F3A6B7B042D28AFC43022E400000000000"
                    "00000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49042EA0B9B3"
                    "4135374ABF789F109AE512FEB53996E081A60C401AE87B3E41767A1961F9D3E09AA9498CF012D5DD6E4A320440"
                    "A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1"
                    "DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M367_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M431_PB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("30820112060B2A86240201010101030101308201013081BC300F020201AF300902010102010302010502010104"
                    "36F3CA40C669A4DA173149CA12C32DAE186B53AC6BC6365997DEAEAE8AD2D888F9BFD53401694EF9C4273D8CFE"
                    "6DC28F706A0F4910CE0302363FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009"
                    "A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF04367C857C94C5433BFD991E17C22684065850A9A249ED7B"
                    "C249AE5A4E878689F872EF7AD524082EC3038E9AEDE7BA6BA13381D979BA621A0440A9D6EB45F13C708280C496"
                    "7B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0"
                    "123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_PB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

#if defined(UTEST_FULL)

static void test_aid_get_dstu4145_params_M173_ONB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081B0060B2A862402010101010301023081A0305C300F020200AD300902010102010202010A0201000416C778"
                    "E2061B65E6E14057914409A03BF41993137E3D0402160800000000000000000000189B4E67606E3825BB283104"
                    "1656EA6D4E4B426ECB1719A5CA1843B28940708D8B3B0A0440A9D6EB45F13C708280C4967B231F5EADF658EBA4"
                    "C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M173_ONB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M179_ONB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081B3060B2A862402010101010301023081A3305F300F020200B330090201010201020201040201010417CBCB"
                    "82216B2E2FC847C56217A6D3938130D84FBC9E9C01021703FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236"
                    "EF0417B8661BB243DE4AACC49BE3D3E059714710542612411F010440A9D6EB45F13C708280C4967B231F5EADF6"
                    "58EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC5"
                    "7904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M179_ONB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M191_ONB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081AE060B2A8624020101010103010230819E305A3007020200BF0201090201010418F81EE3A1139C55AEDB2F"
                    "F74474D50F74EACED6299D1C8713021840000000000000000000000069A779CAC1DABC6788F7474F0418D2851D"
                    "EBBE5AF22A4FB9661BB243DE4AACC49BE3D3E059710440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037"
                    "291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M191_ONB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M233_ONB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("3081C8060B2A862402010101010301023081B83074300F020200E93009020101020104020109020101041E8E9A"
                    "4F2D96E003A0F36446A45AA5EE18C024A404B7752C702A9520F98000021E010000000000000000000000000000"
                    "13E974E72F8A6922031D2603CFE0D7041EFA92992EEC58F7D5925779CA35DB901DF2566225DE1C9F06CF8A3B82"
                    "A0000440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28"
                    "975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M233_ONB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

static void test_aid_get_dstu4145_params_M431_ONB(void)
{
    Dstu4145Ctx *ctx = NULL;
    bool equals = false;
    Dstu4145Ctx *dstu_ctx = NULL;

    AlgorithmIdentifier_t *aid =
            test_aid_from_hex("30820112060B2A86240201010101030102308201013081BC300F020201AF300902010102010302010502010104"
                    "3699925FBA068BFFD51B65433BFE0EE8C5062F3F970FF4535EE66E53194C0A8140F9F183BD46863728AD6BAD26"
                    "F2A6007040B4F77AFB5302363FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009"
                    "A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF0436A6DE5A7CBACF0D09D335B8407EE1E33E8DC048643242"
                    "81B5EBD5A92F57885C4E5D593C775162C1D4BF4A3D367B1524C7D7FC2C1820200440A9D6EB45F13C708280C496"
                    "7B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0"
                    "123E6DB8FAC57904");
    ASSERT_NOT_NULL(aid);

    ASSERT_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M431_ONB));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));

    ASSERT_RET_OK(dstu4145_equals_params(dstu_ctx, ctx, &equals));
    ASSERT_TRUE(equals);

cleanup:

    aid_free(aid);
    dstu4145_free(dstu_ctx);
    dstu4145_free(ctx);
}

#endif

static void test_aid_create_gost28147_cfb(void)
{
    AlgorithmIdentifier_t *aid = NULL;
    OCTET_STRING_t *dke = NULL;
    GOST28147Params_t *params = NULL;
    ByteArray *act_dke_ba = NULL;
    ByteArray *exp_dke_ba =
            ba_alloc_from_le_hex_string("0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");

    ASSERT_RET_OK(aid_create_gost28147_cfb(&aid));
    ASSERT_TRUE(pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID)));
    ASSERT_NOT_NULL(params = asn_any2type(aid->parameters, &GOST28147Params_desc));
    ASSERT_NOT_NULL(dke = asn_copy_with_alloc(&OCTET_STRING_desc, &params->dke));

    ASSERT_RET_OK(asn_encode_ba(&OCTET_STRING_desc, dke, &act_dke_ba));
    ASSERT_EQUALS_BA(exp_dke_ba, act_dke_ba);

cleanup:

    aid_free(aid);
    ASN_FREE(&GOST28147Params_desc, params);
    ASN_FREE(&OCTET_STRING_desc, dke);
    BA_FREE(act_dke_ba, exp_dke_ba);
}

static void test_aid_create_hmac_gost3411(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("300e060a2a8624020101010101020500");

    ASSERT_RET_OK(aid_create_hmac_gost3411(&aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_create_ecdsa_pubkey_P192_R1(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("301306072a8648ce3d020106082a8648ce3d030101");

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P192_R1, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_create_ecdsa_pubkey_P224_R1(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("301006072A8648CE3D020106052B81040021");

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P224_R1, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_create_ecdsa_pubkey_P256_R1(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("301306072a8648ce3d020106082a8648ce3d030107");

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P256_R1, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_create_ecdsa_pubkey_P384_R1(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("301006072a8648ce3d020106052b81040022");

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P384_R1, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_create_ecdsa_pubkey_P521_R1(void)
{
    AlgorithmIdentifier_t *aid_act = NULL;
    ByteArray *encoded = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("301006072a8648ce3d020106052b81040023");

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P521_R1, &aid_act));
    ASSERT_RET_OK(aid_encode(aid_act, &encoded));

    ASSERT_EQUALS_BA(expected, encoded);

cleanup:

    aid_free(aid_act);
    BA_FREE(encoded, expected);
}

static void test_aid_get_ecdsa_params(EcdsaParamsId param)
{
    EcdsaCtx *ctx = NULL;
    EcdsaCtx *act_ctx = NULL;
    ByteArray *exp_a = NULL;
    ByteArray *exp_b = NULL;
    ByteArray *exp_p = NULL;
    ByteArray *exp_q = NULL;
    ByteArray *exp_px = NULL;
    ByteArray *exp_py = NULL;
    ByteArray *act_a = NULL;
    ByteArray *act_b = NULL;
    ByteArray *act_p = NULL;
    ByteArray *act_q = NULL;
    ByteArray *act_px = NULL;
    ByteArray *act_py = NULL;
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_RET_OK(aid_create_ecdsa_pubkey(param, &aid));
    ASSERT_RET_OK(aid_get_ecdsa_params(aid, &act_ctx));
    ASSERT_RET_OK(ecdsa_get_params(act_ctx, &act_p, &act_a, &act_b, &act_q, &act_px, &act_py));

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(param));
    ASSERT_RET_OK(ecdsa_get_params(ctx, &exp_p, &exp_a, &exp_b, &exp_q, &exp_px, &exp_py));

    ASSERT_EQUALS_BA(exp_a, act_a);
    ASSERT_EQUALS_BA(exp_b, act_b);
    ASSERT_EQUALS_BA(exp_p, act_p);
    ASSERT_EQUALS_BA(exp_q, act_q);
    ASSERT_EQUALS_BA(exp_px, act_px);
    ASSERT_EQUALS_BA(exp_py, act_py);

cleanup:

    aid_free(aid);
    ecdsa_free(ctx);
    ecdsa_free(act_ctx);
    BA_FREE(exp_a, exp_b, exp_p, exp_q, exp_px, exp_py, act_a, act_b, act_p, act_q, act_px, act_py);
}

static void test_aid_create_ecdsa_pubkey(void)
{
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_RET(RET_UNSUPPORTED_ECDSA_PARAMS, aid_create_ecdsa_pubkey(ECDSA_PARAMS_ID_SEC_P256_K1 + 1, &aid));
    ASSERT_TRUE(aid == NULL);

cleanup:

    aid_free(aid);
}

static void test_aid_get_ecdsa_params_2(void)
{
    EcdsaCtx *ctx = NULL;
    AlgorithmIdentifier_t *aid = aid_alloc();
    ECParameters_t *ecdsa_params = NULL;
    OidNumbers *oid = NULL;
    ASSERT_RET_OK(aid_init_by_oid(aid, oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID)));

    ASSERT_ASN_ALLOC(ecdsa_params);
    ASSERT_NOT_NULL(oid = oids_get_oid_numbers_by_str("1.1.1"));
    ecdsa_params->present = ECParameters_PR_namedCurve;
    ASSERT_RET_OK(pkix_set_oid(oid, &ecdsa_params->choice.namedCurve));
    ASSERT_RET_OK(asn_create_any(&ECParameters_desc, ecdsa_params, &aid->parameters));

    ASSERT_RET(RET_UNSUPPORTED_ECDSA_PARAMS, aid_get_ecdsa_params(aid, &ctx));
    ASSERT_TRUE(ctx == NULL);

cleanup:

    oids_oid_numbers_free(oid);
    ecdsa_free(ctx);
    aid_free(aid);
    ASN_FREE(&ECParameters_desc, ecdsa_params);
}

static void test_aid_get_dstu4145_params_2(void)
{
    AlgorithmIdentifier_t *aid = aid_alloc();
    Dstu4145Ctx *ctx = NULL;
    OidNumbers *oid = NULL;

    ASSERT_NOT_NULL(oid = oids_get_oid_numbers_by_str("1.1.1"));
    ASSERT_RET_OK(aid_init_by_oid(aid, oid));

    ASSERT_RET(RET_INVALID_PARAM, aid_get_dstu4145_params(aid, &ctx));
    ASSERT_TRUE(ctx == NULL);

cleanup:

    oids_oid_numbers_free(oid);
    dstu4145_free(ctx);
    aid_free(aid);
}

static void test_aid_get_dstu4145_params_3(void)
{
    AlgorithmIdentifier_t *aid = aid_alloc();
    Dstu4145Ctx *ctx = NULL;

    ASSERT_RET_OK(aid_init_by_oid(aid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID)));

    ASSERT_RET_OK(aid_get_dstu4145_params(aid, &ctx));
    ASSERT_TRUE(ctx == NULL);

cleanup:

    dstu4145_free(ctx);
    aid_free(aid);
}

static void test_aid_get_dstu4145_params_4(void)
{
    AlgorithmIdentifier_t *aid = aid_alloc();
    Dstu4145Ctx *ctx = NULL;
    DSTU4145Params_t *dstu_params = NULL;
    OidNumbers *oid = NULL;

    ASSERT_NOT_NULL(oid = oids_get_oid_numbers_by_str("1.1.1"));
    ASSERT_ASN_ALLOC(dstu_params);
    dstu_params->ellipticCurve.present = DSTUEllipticCurve_PR_namedCurve;

    ASSERT_RET_OK(aid_init_by_oid(aid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID)));
    ASSERT_RET_OK(pkix_set_oid(oid, &dstu_params->ellipticCurve.choice.namedCurve));
    ASSERT_RET_OK(asn_create_any(&DSTU4145Params_desc, dstu_params, &aid->parameters));

    ASSERT_RET(RET_PKIX_UNSUPPORTED_DSTU_ELLIPTIC_CURVE_OID, aid_get_dstu4145_params(aid, &ctx));
    ASSERT_TRUE(ctx == NULL);

cleanup:

    oids_oid_numbers_free(oid);
    dstu4145_free(ctx);
    aid_free(aid);
    ASN_FREE(&DSTU4145Params_desc, dstu_params);
}

static void test_aid_init_by_oid(void)
{
    AlgorithmIdentifier_t *aid = aid_alloc();
    OidNumbers *oid = NULL;

    ASSERT_NOT_NULL(oid = oids_get_oid_numbers_by_str("1.1.1"));
    ASSERT_RET(RET_INVALID_PARAM, aid_init_by_oid(NULL, oid));
    ASSERT_RET(RET_INVALID_PARAM, aid_init_by_oid(aid, NULL));

cleanup:

    oids_oid_numbers_free(oid);
    aid_free(aid);
}

static void test_aid_init(void)
{
    AlgorithmIdentifier_t *aid = aid_alloc();
    OBJECT_IDENTIFIER_t *oid = NULL;

    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &oid));
    ASSERT_RET(RET_INVALID_PARAM, aid_init(NULL, oid, NULL, NULL));
    ASSERT_RET(RET_INVALID_PARAM, aid_init(aid, NULL, NULL, NULL));

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    aid_free(aid);
}

#define UTEST_ECDSA_GET_PARAMS(from, to, func)                         \
{                                                                      \
    size_t i = 0;                                                      \
    for (i = from; i <= to; i++) {                                     \
        func((EcdsaParamsId) i);                                       \
    }                                                                  \
}

void utest_aids(void)
{
    AlgorithmIdentifier_t *aid = NULL;

    aid = load_test_data();

    if (aid) {
        test_encode(aid);
        test_init_by_oid(aid);
        test_create_gost3411();
        test_create_gost28147_wrap();
        test_create_gost3411_with_null();
    }

    test_aid_create_dstu4145_M163_PB();
    test_aid_create_dstu4145_M167_PB();
    test_aid_create_dstu4145_M173_PB();
    test_aid_create_dstu4145_M179_PB();
    test_aid_create_dstu4145_M191_PB();
    test_aid_create_dstu4145_M233_PB();
    test_aid_create_dstu4145_M257_PB();
    test_aid_create_dstu4145_M307_PB();
    test_aid_create_dstu4145_M367_PB();
    test_aid_create_dstu4145_M431_PB();
    test_aid_create_dstu4145_pb();

    test_aid_get_dstu4145_params_M163_PB();
    test_aid_get_dstu4145_params_M167_PB();
    test_aid_get_dstu4145_params_M173_PB();
    test_aid_get_dstu4145_params_M179_PB();
    test_aid_get_dstu4145_params_M191_PB();
    test_aid_get_dstu4145_params_M233_PB();
    test_aid_get_dstu4145_params_M257_PB();
    test_aid_get_dstu4145_params_M307_PB();
    test_aid_get_dstu4145_params_M367_PB();
    test_aid_get_dstu4145_params_M431_PB();

    test_aid_create_gost28147_cfb();
    test_aid_create_hmac_gost3411();

    test_aid_create_ecdsa_pubkey_P192_R1();
    test_aid_create_ecdsa_pubkey_P224_R1();
    test_aid_create_ecdsa_pubkey_P256_R1();
    test_aid_create_ecdsa_pubkey_P384_R1();
    test_aid_create_ecdsa_pubkey_P521_R1();

    UTEST_ECDSA_GET_PARAMS(ECDSA_PARAMS_ID_SEC_P192_R1, ECDSA_PARAMS_ID_SEC_P521_R1, test_aid_get_ecdsa_params);

    test_aid_create_ecdsa_pubkey();
    test_aid_get_ecdsa_params_2();
    test_aid_get_dstu4145_params_2();
    test_aid_get_dstu4145_params_3();
    test_aid_get_dstu4145_params_4();

    test_aid_init_by_oid();
    test_aid_init();

#if defined(UTEST_FULL)
    test_aid_create_dstu4145_M173_ONB();
    test_aid_create_dstu4145_M179_ONB();
    test_aid_create_dstu4145_M191_ONB();
    test_aid_create_dstu4145_M233_ONB();
    test_aid_create_dstu4145_M431_ONB();

    test_aid_get_dstu4145_params_M173_ONB();
    test_aid_get_dstu4145_params_M179_ONB();
    test_aid_get_dstu4145_params_M191_ONB();
    test_aid_get_dstu4145_params_M233_ONB();
    test_aid_get_dstu4145_params_M431_ONB();
#endif

    aid_free(aid);
}
