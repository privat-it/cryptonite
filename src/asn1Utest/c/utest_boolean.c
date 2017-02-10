/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static BOOLEAN_t *test_boolean_create_false(void)
{
    uint8_t encode[3] = {0x01, 0x01, 0x00};

    BOOLEAN_t *boolean = NULL;

    ASN_EXECUTE(ber_decode(0, &BOOLEAN_desc, (void *)&boolean, encode, sizeof(encode)));

    ASSERT_NOT_NULL(boolean);
cleanup:
    return boolean;
}

static BOOLEAN_t *test_boolean_create_true(void)
{
    uint8_t encode[3] = {0x01, 0x01, 0xff};
    BOOLEAN_t *boolean = NULL;

    ASN_EXECUTE(ber_decode(0, &BOOLEAN_desc, (void *)&boolean, encode, sizeof(encode)));
    ASSERT_NOT_NULL(boolean);

cleanup:
    return boolean;
}

void test_boolean_alloc_free(void)
{
    BOOLEAN_t *boolean = NULL;

    ASSERT_ASN_ALLOC(boolean);
    ASSERT_NOT_NULL(boolean);
cleanup:
    ASN_FREE(&BOOLEAN_desc, boolean);
}

void test_boolean_encode_true(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[3] = {0x01, 0x01, 0xff};
    BOOLEAN_t *boolean = NULL;

    boolean = test_boolean_create_true();
    ASSERT_NOT_NULL(boolean);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&BOOLEAN_desc, boolean, &actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&BOOLEAN_desc, boolean);
}

void test_boolean_encode_false(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[3] = {0x01, 0x01, 0x00};
    BOOLEAN_t *boolean = NULL;

    boolean = test_boolean_create_false();
    ASSERT_NOT_NULL(boolean);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&BOOLEAN_desc, boolean, &actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&BOOLEAN_desc, boolean);
}

void test_boolean_uper_encode_false(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[1] = {0};
    uint8_t expected[1] = {0x00};

    BOOLEAN_t *boolean = NULL;

    boolean = test_boolean_create_false();
    ASSERT_NOT_NULL(boolean);

    ret = uper_encode_to_buffer(&BOOLEAN_desc, boolean, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&BOOLEAN_desc, boolean);
}

void test_boolean_uper_encode_true(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[1] = {0};
    uint8_t expected[1] = {0x80};

    BOOLEAN_t *boolean = NULL;

    boolean = test_boolean_create_true();
    ASSERT_NOT_NULL(boolean);

    ret = uper_encode_to_buffer(&BOOLEAN_desc, boolean, (void *)actual, 1);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&BOOLEAN_desc, boolean);
}

void test_boolean_uper_decode_false(void)
{
    uint8_t encode[1] = {0x00};

    BOOLEAN_t *actual = NULL;
    BOOLEAN_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_boolean_create_false();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &BOOLEAN_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&BOOLEAN_desc, expected, actual));
cleanup:
    ASN_FREE(&BOOLEAN_desc, expected);
    ASN_FREE(&BOOLEAN_desc, actual);
}

void test_boolean_uper_decode_true(void)
{
    uint8_t encode[1] = {0x80};

    BOOLEAN_t *actual = NULL;
    BOOLEAN_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_boolean_create_true();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &BOOLEAN_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&BOOLEAN_desc, expected, actual));
cleanup:
    ASN_FREE(&BOOLEAN_desc, expected);
    ASN_FREE(&BOOLEAN_desc, actual);
}

void test_boolean_xer_decode_false(void)
{
    uint8_t encode[27] = {
        0x3c, 0x42, 0x4f, 0x4f, 0x4c, 0x45, 0x41, 0x4e,
        0x3e, 0x3c, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x2f,
        0x3e, 0x3c, 0x2f, 0x42, 0x4f, 0x4f, 0x4c, 0x45,
        0x41, 0x4e, 0x3e
    };

    BOOLEAN_t *actual = NULL;
    BOOLEAN_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_boolean_create_false();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &BOOLEAN_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&BOOLEAN_desc, expected, actual));
cleanup:
    ASN_FREE(&BOOLEAN_desc, expected);
    ASN_FREE(&BOOLEAN_desc, actual);
}

void test_boolean_xer_decode_true(void)
{
    uint8_t encode[26] = {
        0x3c, 0x42, 0x4f, 0x4f, 0x4c, 0x45, 0x41, 0x4e,
        0x3e, 0x3c, 0x74, 0x72, 0x75, 0x65, 0x2f, 0x3e,
        0x3c, 0x2f, 0x42, 0x4f, 0x4f, 0x4c, 0x45, 0x41,
        0x4e, 0x3e
    };

    BOOLEAN_t *actual = NULL;
    BOOLEAN_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_boolean_create_true();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &BOOLEAN_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&BOOLEAN_desc, expected, actual));

cleanup:
    ASN_FREE(&BOOLEAN_desc, expected);
    ASN_FREE(&BOOLEAN_desc, actual);
}

void utest_boolean(void)
{
    PR("%s\n", __FILE__);

    test_boolean_alloc_free();
    test_boolean_encode_true();
    test_boolean_encode_false();
    test_boolean_uper_encode_false();
    test_boolean_uper_encode_true();
    test_boolean_uper_decode_false();
    test_boolean_uper_decode_true();
    test_boolean_xer_decode_false();
    test_boolean_xer_decode_true();
}
