/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "utest.h"
#include "word_internal.h"
#include "math_ecp_internal.h"
#include "math_ec_point_internal.h"

void ecp_add_point(const EcGfpCtx *ctx, const ECPoint *p, const WordArray *qx, const WordArray *qy, int sign,
        ECPoint *r);
void ecp_point_to_affine(const EcGfpCtx *ctx, ECPoint *p);

typedef struct EcpTestData_st {
    EcGfpCtx *ctx;
    ECPoint *P;
    ECPoint *Q;
} EcpTestData;

static EcpTestData *ecp_test_data_init(void)
{
    WordArray *p = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *a = wa_alloc_from_be_hex_string("0000000000000000000000000000000000000000000000000000000000000007");
    WordArray *b = wa_alloc_from_be_hex_string("5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e");
    WordArray *px = wa_alloc_from_be_hex_string("0000000000000000000000000000000000000000000000000000000000000002");
    WordArray *py = wa_alloc_from_be_hex_string("08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8");
    WordArray *qx = wa_alloc_from_be_hex_string("5300ed9dfa5efed73f12991168761ba52faa68ad4ada5fb161af6c6407b59bba");
    WordArray *qy = wa_alloc_from_be_hex_string("2a01f2cbd4dcea9d4cee378f6c51818a2fe4e866252ea8a78bb5909344659234");

    EcpTestData *td = malloc(sizeof(EcpTestData));
    td->ctx = ecp_alloc(p, a, b);
    td->P = ec_point_aff_alloc(px, py);
    td->Q = ec_point_aff_alloc(qx, qy);

    wa_free(p);
    wa_free(a);
    wa_free(b);
    wa_free(px);
    wa_free(py);
    wa_free(qx);
    wa_free(qy);

    return td;
}

static void ecp_point_to_affine_test(EcpTestData *td)
{
    WordArray *qx = wa_alloc_from_be_hex_string("677ac4eedbf00837934048f9f84d8acf7bb5b0f68be8c1147e639346808b0153");
    WordArray *qy = wa_alloc_from_be_hex_string("0a9dccc14821852a0b41e0fd41839c61a0a11ea6818e2799ef160e2822ae657d");
    WordArray *qz = wa_alloc_from_be_hex_string("7b724559ef3beaf3bc6f86c4ab2c8254699126cb44f697373319fbc832cdedc6");

    ECPoint *Q = ec_point_proj_alloc(qx, qy, qz);

    ecp_point_to_affine(td->ctx, Q);

    ASSERT_EQUALS_WA(td->P->x, Q->x);
    ASSERT_EQUALS_WA(td->P->y, Q->y);
    ASSERT_EQUALS_WA(td->P->z, Q->z);

    ec_point_free(Q);
    wa_free(qx);
    wa_free(qy);
    wa_free(qz);
}

static void ecp_is_on_curve_test(EcpTestData *td)
{
    ASSERT_TRUE(ecp_is_on_curve(td->ctx, td->Q->x, td->Q->y));
}

static void ecp_add_test(EcpTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("44ade03bb9757ae320fd6eaa759fe2a373e4c9a14b496763e1ba100a2783a1b6");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("5b17111aa2fcdce4dc894fb481fad5498017f47f5e0fc629145149d9d22c86a5");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);
    ecp_add_point(td->ctx, td->P, td->Q->x, td->Q->y, 1, R);
    ecp_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ecp_sub_test(EcpTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("42fb9eceaa5d3da4987fc15cd49d7d023f2483efe7346e4eb44bd6fc57f55711");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("7bbd658965b8a2fb7595af2637fae33bd9aaad2c501563b91ee45f132d71f93c");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ecp_add_point(td->ctx, td->P, td->Q->x, td->Q->y, -1, R);
    ecp_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ecp_double_test(EcpTestData *td)
{
    WordArray *rx_exp = wa_alloc_from_be_hex_string("0d750f5c72c129367c8af0e2490a495dbd512efdab4da0cb3bcd357d2fa4d3de");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("1bd1a947a3365692f024ee1f9bd5052d597c11e7edc62ac0624f47d9cc386b32");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ecp_add_point(td->ctx, td->Q, td->Q->x, td->Q->y, 1, R);
    ecp_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ecp_mul_test(EcpTestData *td)
{
    WordArray *k = wa_alloc_from_be_hex_string("53b7f9884a337c975998b0b2bbbfafe0d6ff6e663376f920544306e9dae23b77");
    WordArray *rx_exp = wa_alloc_from_be_hex_string("3fdbdc35ce5129937c4d44d4cda0bcc6372fb2075dac51310ff99d098126aadb");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("74361b924f20efd8d4eaaf58365d6220940bf8c858b6db81893716895545d715");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ecp_mul(td->ctx, td->P, k, R);
    ecp_point_to_affine(td->ctx, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(k);
    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ecp_dual_mul_test(EcpTestData *td)
{
    WordArray *m = wa_alloc_from_be_hex_string("53b7f9884a337c975998b0b2bbbfafe0d6ff6e663376f920544306e9dae23b77");
    WordArray *n = wa_alloc_from_be_hex_string("437799482a639c9459a8a0c2bbdfefe0d6ff3e669870f92055470989dae43679");
    WordArray *rx_exp = wa_alloc_from_be_hex_string("320c31dc9fa06dd44b3f2e2eae40ca75a45421e9e51cd3b4580983d89227d356");
    WordArray *ry_exp = wa_alloc_from_be_hex_string("1e7a8e136d9f2c9c6c48495478a60c0e76e929324b01f301d7d538823c2b53c2");
    ECPoint *R = NULL;
    size_t len = td->ctx->len;

    R = ec_point_alloc(len);

    ecp_dual_mul(td->ctx, td->P, m, td->Q, n, R);

    ASSERT_EQUALS_WA(rx_exp, R->x);
    ASSERT_EQUALS_WA(ry_exp, R->y);

    wa_free(m);
    wa_free(n);
    wa_free(rx_exp);
    wa_free(ry_exp);
    ec_point_free(R);
}

static void ecp_test_data_free(EcpTestData *td)
{
    ec_point_free(td->P);
    ec_point_free(td->Q);
    ecp_free(td->ctx);
    free(td);
}


void utest_math_ecp(void)
{
    PR("%s\n", __FILE__);

    EcpTestData *td = ecp_test_data_init();

    ecp_point_to_affine_test(td);
    ecp_is_on_curve_test(td);
    ecp_add_test(td);
    ecp_sub_test(td);
    ecp_double_test(td);
    ecp_mul_test(td);
    ecp_dual_mul_test(td);

    ecp_test_data_free(td);
}
