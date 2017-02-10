/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static INTEGER_t *test_integer_create(void)
{
    uint8_t encode[6] = {
        0x02, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    INTEGER_t *integer = NULL;

    ASN_EXECUTE(ber_decode(0, &INTEGER_desc, (void *)&integer, encode, sizeof(encode)));

    ASSERT_NOT_NULL(integer);
cleanup:
    return integer;
}

void test_integer_alloc_free(void)
{
    INTEGER_t *integer = NULL;


    ASSERT_ASN_ALLOC(integer);
    ASSERT_NOT_NULL(integer);

cleanup:

    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[6] = {
        0x02, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    INTEGER_t *integer = NULL;

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&INTEGER_desc, integer, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[40] = {0};
    uint8_t expected[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    INTEGER_t *integer = NULL;

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);

    ret = uper_encode_to_buffer(&INTEGER_desc, integer, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_uper_decode(void)
{
    uint8_t encode[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    INTEGER_t *actual = NULL;
    INTEGER_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_integer_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &INTEGER_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));
cleanup:
    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&INTEGER_desc, actual);
}

void test_integer_xer_decode(void)
{
    uint8_t encode[27] = {
        0x3C, 0x49, 0x4E, 0x54,
        0x45, 0x47, 0x45, 0x52,
        0x3E, 0x38, 0x34, 0x32,
        0x38, 0x31, 0x30, 0x39,
        0x36, 0x3C, 0x2F, 0x49,
        0x4E, 0x54, 0x45, 0x47,
        0x45, 0x52, 0x3E
    };

    INTEGER_t *actual = NULL;
    INTEGER_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_integer_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &INTEGER_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));
cleanup:
    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&INTEGER_desc, actual);
}

void test_integer_asn_INTEGER2long(void)
{
    long expected = 84281096;
    long actual = 0;
    INTEGER_t *integer = NULL;

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);

    ASSERT_RET_OK(asn_INTEGER2long(integer, &actual));

    ASSERT_TRUE(expected == actual);
cleanup:
    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_asn_INTEGER2ulong(void)
{
    unsigned long expected = 84281096;
    unsigned long actual = 0;
    INTEGER_t *integer = NULL;

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);

    ASSERT_RET_OK(asn_INTEGER2ulong(integer, &actual));

    ASSERT_TRUE(expected == actual);

cleanup:

    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_asn_INTEGER2bytes(void)
{
    size_t actual_len = 0;
    size_t expected_len = 4;
    uint8_t *actual = NULL;
    uint8_t expected[4] = {0x05, 0x06, 0x07, 0x08};

    INTEGER_t *integer = NULL;

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);

    ASSERT_RET_OK(asn_INTEGER2bytes(integer, &actual, &actual_len));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(expected_len == actual_len);
    ASSERT_EQUALS(expected, actual, expected_len);
cleanup:
    free(actual);
    ASN_FREE(&INTEGER_desc, integer);
}

void test_integer_asn_long2INTEGER(void)
{
    INTEGER_t *actual = NULL;
    INTEGER_t *expected = NULL;


    expected = test_integer_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(asn_long2INTEGER(actual, 84281096));

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));

cleanup:

    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&INTEGER_desc, actual);
}

void test_integer_asn_ulong2INTEGER(void)
{
    INTEGER_t *actual = NULL;
    INTEGER_t *expected = NULL;

    expected = test_integer_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(asn_ulong2INTEGER(actual, 84281096));

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));
cleanup:
    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&INTEGER_desc, actual);
}

void test_integer_asn_bytes2INTEGER(void)
{
    uint8_t value[4] = {0x05, 0x06, 0x07, 0x08};
    INTEGER_t *actual = NULL;
    INTEGER_t *expected = NULL;

    expected = test_integer_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(asn_bytes2INTEGER(actual, value, sizeof(value)));

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));
cleanup:
    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&INTEGER_desc, actual);
}

void utest_integer(void)
{
    PR("%s\n", __FILE__);

    test_integer_alloc_free();
    test_integer_uper_encode();
    test_integer_der_encode();
    test_integer_uper_decode();
    test_integer_xer_decode();
    test_integer_asn_INTEGER2long();
    test_integer_asn_INTEGER2ulong();
    test_integer_asn_INTEGER2bytes();
    test_integer_asn_long2INTEGER();
    test_integer_asn_ulong2INTEGER();
    test_integer_asn_bytes2INTEGER();
}
