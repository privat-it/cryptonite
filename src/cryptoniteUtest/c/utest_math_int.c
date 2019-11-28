/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "word_internal.h"
#include "math_int_internal.h"

#ifdef DWORD_OWN
void word_div_own(Dword *a, word_t b, Dword *q, word_t *r);
void words_div_own(const word_t *a, const word_t *b, int len, word_t *q, word_t *r);

static void static_word_div_own(void)
{
    Dword a = {0x12345678, 0x2468acf0};
    word_t b = 0x12345678;
    Dword q;
    word_t r[1];
    Dword exp = {1, 2};

    word_div_own(&a, b, &q, r);

    ASSERT_EQUALS(&exp.lo, &q.lo, 2 * sizeof(word_t));
}

static void static_words_div_own(void)
{
    WordArray *a = wa_from_be_hex_string("000000000000000000f7f6a8a6f56a5f8f73a2f658f2a7a3f65823f6e58276c1");
    WordArray *b = wa_from_be_hex_string("000000000a98b678a965b654a78b900a");
    WordArray *q = wa_zero_with_alloc(a->len);
    WordArray *r = wa_zero_with_alloc(b->len);
    WordArray *exp = wa_from_be_hex_string("000000000000000000000000000000000000000176682e6ecbc286973627b5e");

    words_div_own(a->buf, b->buf, b->len, q->buf, r->buf);
    ASSERT_EQUALS_WA(exp, q);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp);
}

#endif

#ifdef DWORD_STD
void word_div_std(dword_t a, word_t b, dword_t *q, word_t *r);
void words_div_std(const word_t *a, const word_t *b, size_t len, word_t *q, word_t *r);

//static void static_word_div_std(void)
//{
//    dword_t a = ((dword_t)(((dword_t)0x9cc920976b28a46a) << 64)) | (dword_t)0x86e2aa7f65823f6e;
//    word_t b = 0xa98b678a965b654a;
//    dword_t q;
//    word_t r;
//    dword_t exp = 0xecbc286973627b5f;
//
//    word_div_std(a, b, &q, &r);
//
//    ASSERT_EQUALS(&exp, &q, sizeof(dword_t));
//}

static void static_words_div_std(void)
{
    WordArray *a = wa_from_be_hex_string("000000000000000000f7f6a8a6f56a5f8f73a2f658f2a7a3f65823f6e58276c1");
    WordArray *b = wa_from_be_hex_string("000000000a98b678a965b654a78b900a");
    WordArray *q = wa_zero_with_alloc(a->len);
    WordArray *r = wa_zero_with_alloc(b->len);
    WordArray *exp = wa_from_be_hex_string("000000000000000000000000000000000000000176682e6ecbc286973627b5e");

    words_div_std(a->buf, b->buf, b->len, q->buf, r->buf);
    ASSERT_EQUALS_WA(exp, q);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp);
}

#endif

static void int_add_test(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("173de2965cf7b2433dad8c8bbe4129a09ff7266b4fc0de92a80fabd2fab81206");
    WordArray *b = wa_alloc_from_be_hex_string("29fa4ea390474d027bddb12e9268dd53177c539c8989bbdb820fa51193c24a70");
    WordArray *act = wa_alloc_with_zero(a->len);
    WordArray *exp = wa_alloc_from_be_hex_string("41383139ed3eff45b98b3dba50aa06f3b7737a07d94a9a6e2a1f50e48e7a5c76");

    int_add(a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(b);
    wa_free(act);
    wa_free(exp);
}

static void int_mul_test(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("173de2965cf7b2433dad8c8bbe4129a09ff7266b4fc0de92a80fabd2fab81206");
    WordArray *b = wa_alloc_from_be_hex_string("29fa4ea390474d027bddb12e9268dd53177c539c8989bbdb820fa51193c24a70");
    WordArray *act = wa_alloc_with_zero(2 * a->len);
    WordArray *exp = wa_alloc_from_be_hex_string(
            "3cfa2dd1044d41dc772fd1524b566c0926918a0ac24fef52b14fbcd7b74d3eeaccb02b36df1fdf1eec2da6dd5bc15dd1777d6a2c9ab7bf5ce90eb0400499ea0");

    int_mul(a, b, act);
    ASSERT_EQUALS_WA(exp, act);

    wa_free(a);
    wa_free(b);
    wa_free(act);
    wa_free(exp);
}

static void int_div_test1(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("4BCC0130F40762CD4BCC0130F40762CE");
    WordArray *b = wa_alloc_from_be_hex_string("4BCC0130F40762CD");
    WordArray *q = wa_alloc_with_zero(a->len);
    WordArray *r = wa_alloc_with_zero(b->len);
    WordArray *exp_q = wa_alloc_from_be_hex_string("00000000000000010000000000000001");
    WordArray *exp_r = wa_alloc_from_be_hex_string("0000000000000001");

    int_div(a, b, q, r);
    ASSERT_EQUALS_WA(exp_q, q);
    ASSERT_EQUALS_WA(exp_r, r);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp_q);
    wa_free(exp_r);
}

static void int_div_test2(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("000000000000000000f7f6a8a6f56a5f8f73a2f658f2a7a3f65823f6e58276c1");
    WordArray *b = wa_alloc_from_be_hex_string("000000000a98b678a965b654a78b900a");
    WordArray *q = wa_alloc_with_zero(a->len);
    WordArray *r = wa_alloc_with_zero(b->len);
    WordArray *exp_q = wa_alloc_from_be_hex_string("000000000000000000000000000000000000000176682e6ecbc286973627b5e");
    WordArray *exp_r = wa_alloc_from_be_hex_string("000000000690f0f08aa10b25b03ac515");

    int_div(a, b, q, r);

    ASSERT_EQUALS_WA(exp_q, q);
    ASSERT_EQUALS_WA(exp_r, r);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp_q);
    wa_free(exp_r);
}

static void int_div_test3(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("bf433e69b59296b99a64289ce808b3db8a385c6c05c284a8b5b435a7fe52779328f");
    WordArray *b = wa_alloc_from_be_hex_string("89ff0132deea20f7264ffc0bc23e03c");
    WordArray *exp_q = wa_alloc_from_be_hex_string("162d0eca5ad8155eb670d5b0b9bdcf2f3481e");
    WordArray *exp_r = wa_alloc_from_be_hex_string("a7e89684054ce51f9ccace73400b87");
    WordArray *q = wa_alloc_with_zero(a->len);
    WordArray *r = wa_alloc_with_zero(b->len);

    size_t n = (a->len > 2 * b->len) ? (a->len + 1) / 2 : b->len;

    wa_change_len(a, 2 * n);
    wa_change_len(b, n);
    wa_change_len(q, 2 * n);
    wa_change_len(r, n);
    wa_change_len(exp_q, 2 * n);
    wa_change_len(exp_r, n);

    int_div(a, b, q, r);
    ASSERT_EQUALS_WA(exp_q, q);
    ASSERT_EQUALS_WA(exp_r, r);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp_q);
    wa_free(exp_r);
}

static void int_div_test4(void)
{
    WordArray *a = wa_alloc_from_be_hex_string("800000000000000000000000000000000000000000000000000000000000042c");
    WordArray *b = wa_alloc_from_be_hex_string("8000000000000000000000000000000000000000000000000000000000000431");
    WordArray *exp_q = wa_alloc_from_be_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    WordArray *exp_r = wa_alloc_from_be_hex_string("800000000000000000000000000000000000000000000000000000000000042c");
    WordArray *q = wa_alloc_with_zero(a->len);
    WordArray *r = wa_alloc_with_zero(b->len);
    wa_change_len(a, 2 * WA_LEN_FROM_BITS(256));
    wa_change_len(exp_q, 2 * WA_LEN_FROM_BITS(256));

    size_t n = (a->len > 2 * b->len) ? (a->len + 1) / 2 : b->len;

    wa_change_len(a, 2 * n);
    wa_change_len(b, n);
    wa_change_len(q, 2 * n);
    wa_change_len(r, n);
    wa_change_len(exp_q, 2 * n);
    wa_change_len(exp_r, n);

    int_div(a, b, q, r);
    ASSERT_EQUALS_WA(exp_q, q);
    ASSERT_EQUALS_WA(exp_r, r);

    wa_free(a);
    wa_free(b);
    wa_free(q);
    wa_free(r);
    wa_free(exp_q);
    wa_free(exp_r);
}
#ifdef FULL_UTEST
static void int_gen_prime_number_test()
{
    PrngCtx *prng = NULL;
    WordArray *prime = NULL;

    prng = test_utils_get_prng();

    size_t basic_bit_len = 512;
    for (size_t bit_num = basic_bit_len; bit_num < basic_bit_len + WORD_BIT_LENGTH; bit_num++) {
        printf("bit_num: %d\n", bit_num);
        int_gen_prime(bit_num, prng, &prime);

        size_t prime_bit_len = int_bit_len(prime);
        ASSERT_TRUE(prime_bit_len == bit_num)

        wa_free(prime);
        prime = NULL;
    }

cleanup:

    prng_free(prng);
    wa_free(prime);
}
#endif

static void test_fermat_primary(void)
{
    WordArray *wa = wa_alloc_from_be_hex_string("01A1B0330792CC33D4358290085336C31BBDBED57E756A73A6B7AAA46A0E25241B");
    bool is_prime = false;

    ASSERT_RET_OK(int_fermat_primary_test(wa, &is_prime))
    ASSERT_TRUE(is_prime);

cleanup:

    wa_free(wa);
}

static void test_rabin_miller_primary(void)
{
    WordArray *wa = wa_alloc_from_be_hex_string("01A1B0330792CC33D4358290085336C31BBDBED57E756A73A6B7AAA46A0E25241B");
    bool is_prime = false;

    ASSERT_RET_OK(int_rabin_miller_primary_test(wa, &is_prime))
    ASSERT_TRUE(is_prime);

cleanup:

    wa_free(wa);
}

void utest_math_int(void)
{
    PR("%s\n", __FILE__);

#ifdef DWORD_OWN
    static_word_div_own();
    static_words_div_own();
#endif

#ifdef DWORD_STD
//    static_word_div_std();
    static_words_div_std();
#endif

    int_add_test();
    int_mul_test();
    int_div_test1();
    int_div_test2();
    int_div_test3();
    int_div_test4();
    test_fermat_primary();
    test_rabin_miller_primary();
#ifdef FULL_UTEST
    int_gen_prime_number_test();
#endif

}
