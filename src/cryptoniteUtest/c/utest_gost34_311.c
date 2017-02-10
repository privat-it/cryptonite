/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "gost34_311.h"

static void gost34_311_test_1(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *data = ba_alloc_from_le_hex_string("ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "02d7e8a3c111788bb1b8a489c5e330288728f1c308c2cec08e09265bfa395599");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_1_copy_with_alloc(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *data = ba_alloc_from_le_hex_string("ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "02d7e8a3c111788bb1b8a489c5e330288728f1c308c2cec08e09265bfa395599");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
    Gost34311Ctx *ctx_copy = NULL;

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_NOT_NULL(ctx_copy = gost34_311_copy_with_alloc(ctx));
    gost34_311_free(ctx);
    ctx = NULL;
    ASSERT_RET_OK(gost34_311_final(ctx_copy, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    gost34_311_free(ctx_copy);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_2(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    ByteArray *data = ba_alloc_from_le_hex_string("cd944dc9951b5e1eea4a9ebca4e30e4568d48f640d9b228e2df398f767b4eaab");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "30667bae2a36245ce8abd0e8f84812df7ffd7dfee6289ef6d79624d709f97208");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_2_copy_with_alloc(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    ByteArray *data = ba_alloc_from_le_hex_string("cd944dc9951b5e1eea4a9ebca4e30e4568d48f640d9b228e2df398f767b4eaab");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "30667bae2a36245ce8abd0e8f84812df7ffd7dfee6289ef6d79624d709f97208");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);
    Gost34311Ctx *ctx_copy = NULL;

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_NOT_NULL(ctx_copy = gost34_311_copy_with_alloc(ctx));
    gost34_311_free(ctx);
    ctx = NULL;
    ASSERT_RET_OK(gost34_311_final(ctx_copy, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    gost34_311_free(ctx_copy);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_3(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    ByteArray *data = ba_alloc_from_le_hex_string(
            "9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691d9e4abc889632959d73e0bf139cd71813ebee679e930");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_4(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    ByteArray *data1 = ba_alloc_from_le_hex_string("9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691");
    ByteArray *data2 = ba_alloc_from_le_hex_string("d9e4abc889632959d73e0bf139cd71813ebee679e9");
    ByteArray *data3 = ba_alloc_from_le_hex_string("30");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data1));
    ASSERT_RET_OK(gost34_311_update(ctx, data2));
    ASSERT_RET_OK(gost34_311_update(ctx, data3));
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    ba_free(sync);
    ba_free(data1);
    ba_free(data2);
    ba_free(data3);
    ba_free(expected);
    ba_free(actual);
}

static void gost34_311_test_5(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *data = ba_alloc();
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_11, sync);

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(gost34_311_update(ctx, data));
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    gost34_311_free(ctx);
    ba_free(sync);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

#ifdef UTEST_FULL

static void gost34_311_test_6(void)
{
    ByteArray *sync = ba_alloc_by_len(32);
    ByteArray *data = ba_alloc_by_len(1000);
    ByteArray *exp = ba_alloc_from_le_hex_string("63d95e744ba170c3b25fe49c514adaa35a682b3ddfc902c3e694ffa5520eda84");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = NULL;
    int i = 0;

    ba_set(sync, 0);
    ba_set(data, 0);

    ASSERT_NOT_NULL(ctx = gost34_311_alloc(GOST28147_SBOX_ID_11, sync));
    for (i = 0; i < 600000; i++) {
        ASSERT_RET_OK(gost34_311_update(ctx, data));
    }
    ASSERT_RET_OK(gost34_311_final(ctx, &actual));
    ASSERT_EQUALS_BA(exp, actual);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(actual);
    ba_free(sync);
    gost34_311_free(ctx);
}

#endif

void utest_gost34311(void)
{
    PR("%s\n", __FILE__);

    gost34_311_test_1();
    gost34_311_test_2();
    gost34_311_test_3();
    gost34_311_test_4();
    gost34_311_test_5();
    gost34_311_test_1_copy_with_alloc();
    gost34_311_test_2_copy_with_alloc();
#ifdef UTEST_FULL
    gost34_311_test_6();
#endif
}
