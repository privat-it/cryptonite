/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "utest.h"
#include "word_internal.h"
#include "math_ec2m_internal.h"
#include "math_ec_point_internal.h"

void ec2m_add(const EcGf2mCtx *ctx, const ECPoint *p, const WordArray *qx, const WordArray *qy, int sign, ECPoint *r);

typedef struct Ec2mTestData_st {
    EcGf2mCtx *ctx;
    ECPoint *P;
    ECPoint *Q;
} Ec2mTestData;

static Ec2mTestData *ec2m_test_data_init(void)
{
    int f[] = {163, 7, 6, 3, 0};
    int a = 1;
    WordArray *b = wa_alloc_from_be_hex_string("00000005ff6108462a2dc8210ab403925e638a19c1455d21");
    WordArray *px = wa_alloc_from_be_hex_string("000000072d867f93a93ac27df9ff01affe74885c8c540420");
    WordArray *py = wa_alloc_from_be_hex_string("00000000224a9c3947852b97c5599d5f4ab81122adc3fd9b");
    WordArray *qx = wa_alloc_from_be_hex_string("000000008110f52a2ae552427bf9c2f206dbe434f424a76b");
    WordArray *qy = wa_alloc_from_be_hex_string("0000000054441b6b92939fdfa7cc0dce52c769701691ac84");

    Ec2mTestData *td = malloc(sizeof(Ec2mTestData));

    td->ctx = ec2m_alloc(f, sizeof(f) / sizeof(int), a, b);
    td->P = ec_point_aff_alloc(px, py);
    td->Q = ec_point_aff_alloc(qx, qy);

    wa_free(b);
    wa_free(px);
    wa_free(py);
    wa_free(qx);
    wa_free(qy);

    return td;
}

static void ec2m_is_on_curve_test(Ec2mTestData *td)
{
    ASSERT_TRUE(ec2m_is_on_curve(td->ctx, td->Q->x, td->Q->y));
}

static void ec2m_add_test(Ec2mTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("000000066f0e9a42810c21dcc3573043e7a6e10727925e7c");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("0000000555aab1cd55c3b0d67d17bb7a9d28f548fb980783");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);
    ec2m_add(td->ctx, td->P, td->Q->x, td->Q->y, 1, R);
    ec2m_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ec2m_sub_test(Ec2mTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("00000001e67ba30e7775f373f62c8fb61836a2fecdbd8008");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("00000002d45c4b53b8f7d11199f08aeeb7c79411a31910e1");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ec2m_add(td->ctx, td->P, td->Q->x, td->Q->y, -1, R);
    ec2m_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ec2m_double_test(Ec2mTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("000000027170e40b937737391674d54681cc2e914f069eca");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("00000005a699f5a66c0af086f01a189cb919774e476656b6");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ec2m_add(td->ctx, td->Q, td->Q->x, td->Q->y, 1, R);
    ec2m_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ec2m_mul_test(Ec2mTestData *td)
{
    WordArray *k = wa_alloc_from_be_hex_string("00000002bbbfafe0d6ff6e5dfc089ba00bf56c8f2fc5e431");
    WordArray *rx_exp = wa_alloc_from_be_hex_string("000000008110f52a2ae552427bf9c2f206dbe434f424a76b");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("0000000054441b6b92939fdfa7cc0dce52c769701691ac84");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ec2m_mul(td->ctx, td->P, k, R);
    ec2m_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(k);
    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ec2m_dual_mul_test(Ec2mTestData *td)
{
    WordArray *k = wa_alloc_from_be_hex_string("00000002bbbfafe0d6ff6e5dfc089ba00bf56c8f2fc5e431");
    WordArray *n = wa_alloc_from_be_hex_string("0000000563676578f7946ff6e5dfc089b578bf56c8f335c7");
    WordArray *rx_exp = wa_alloc_from_be_hex_string("0000000532da0cf67aa06a4097b0e3f67babd2fab0982e2e");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("00000001701842a617e5ac49bb48f2c11da4b851c87260c7");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ec2m_dual_mul(td->ctx, td->P, k, td->Q, n, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(k);
    wa_free(n);
    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ec2m_test_data_free(Ec2mTestData *td)
{
    ec_point_free(td->P);
    ec_point_free(td->Q);
    ec2m_free(td->ctx);
    free(td);
}

void utest_math_ec2m(void)
{
    PR("%s\n", __FILE__);

    Ec2mTestData *td = ec2m_test_data_init();

    ec2m_is_on_curve_test(td);
    ec2m_add_test(td);
    ec2m_sub_test(td);
    ec2m_double_test(td);
    ec2m_mul_test(td);
    ec2m_dual_mul_test(td);

    ec2m_test_data_free(td);
}
