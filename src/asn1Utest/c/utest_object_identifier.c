/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static OBJECT_IDENTIFIER_t *test_object_identifier_create(void)
{
    uint8_t encode[6] = {
        0x06, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    OBJECT_IDENTIFIER_t *object_identifier = NULL;

    ASN_EXECUTE(ber_decode(0, &OBJECT_IDENTIFIER_desc, (void *)&object_identifier, encode, sizeof(encode)));

    ASSERT_NOT_NULL(object_identifier);
cleanup:
    return object_identifier;
}

void test_object_identifier_alloc_free(void)
{
    OBJECT_IDENTIFIER_t *object_identifier = NULL;


    ASSERT_ASN_ALLOC(object_identifier);
    ASSERT_NOT_NULL(object_identifier);
cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, object_identifier);
}

void test_object_identifier_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[6] = {
        0x06, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    OBJECT_IDENTIFIER_t *object_identifier = NULL;

    object_identifier = test_object_identifier_create();
    ASSERT_NOT_NULL(object_identifier);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&OBJECT_IDENTIFIER_desc, object_identifier, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, object_identifier);
}

void test_object_identifier_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[40] = {0};
    uint8_t expected[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    OBJECT_IDENTIFIER_t *object_identifier = NULL;

    object_identifier = test_object_identifier_create();
    ASSERT_NOT_NULL(object_identifier);

    ret = uper_encode_to_buffer(&OBJECT_IDENTIFIER_desc, object_identifier, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, object_identifier);
}

void test_object_identifier_uper_decode(void)
{
    uint8_t encode[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    OBJECT_IDENTIFIER_t *actual = NULL;
    OBJECT_IDENTIFIER_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_object_identifier_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &OBJECT_IDENTIFIER_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&OBJECT_IDENTIFIER_desc, expected, actual));

cleanup:
    ASN_FREE(&OBJECT_IDENTIFIER_desc, expected);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, actual);
}

void test_object_identifier_xer_decode(void)
{
    uint8_t encode[48] = {
        0x3c, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f,
        0x49, 0x44, 0x45, 0x4e, 0x54, 0x49, 0x46, 0x49,
        0x45, 0x52, 0x3e, 0x30, 0x2e, 0x35, 0x2e, 0x36,
        0x2e, 0x37, 0x2e, 0x38, 0x3c, 0x2f, 0x4f, 0x42,
        0x4a, 0x45, 0x43, 0x54, 0x5f, 0x49, 0x44, 0x45,
        0x4e, 0x54, 0x49, 0x46, 0x49, 0x45, 0x52, 0x3e
    };

    OBJECT_IDENTIFIER_t *actual = NULL;
    OBJECT_IDENTIFIER_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_object_identifier_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &OBJECT_IDENTIFIER_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&OBJECT_IDENTIFIER_desc, expected, actual));

cleanup:
    ASN_FREE(&OBJECT_IDENTIFIER_desc, expected);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, actual);
}

void test_object_identifier_OBJECT_IDENTIFIER_get_arcs(void)
{
    size_t actual_len = 0;
    size_t expected_len = 5;
    int actual[10] = {0};
    int expected[5] = {0, 5, 6, 7, 8};

    OBJECT_IDENTIFIER_t *object_identifier = NULL;

    object_identifier = test_object_identifier_create();
    ASSERT_NOT_NULL(object_identifier);

    actual_len = OBJECT_IDENTIFIER_get_arcs(object_identifier,
            actual,
            sizeof(int),
            sizeof(actual) / sizeof(int));

    ASSERT_TRUE(expected_len == actual_len);
    ASSERT_EQUALS(expected, actual, expected_len);
cleanup:
    ASN_FREE(&OBJECT_IDENTIFIER_desc, object_identifier);
}

void test_object_identifier_OBJECT_IDENTIFIER_set_arcs(void)
{
    int value[5] = {0, 5, 6, 7, 8};
    OBJECT_IDENTIFIER_t *actual = NULL;
    OBJECT_IDENTIFIER_t *expected = NULL;

    expected = test_object_identifier_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(OBJECT_IDENTIFIER_set_arcs(actual,
            value,
            sizeof(int),
            sizeof(value) / sizeof(int)));

    ASSERT_TRUE(asn_equals(&OBJECT_IDENTIFIER_desc, expected, actual));

cleanup:
    ASN_FREE(&OBJECT_IDENTIFIER_desc, expected);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, actual);
}

void utest_object_identifier(void)
{
    PR("%s\n", __FILE__);

    test_object_identifier_alloc_free();
    test_object_identifier_uper_encode();
    test_object_identifier_der_encode();
    test_object_identifier_uper_decode();
    test_object_identifier_xer_decode();
    test_object_identifier_OBJECT_IDENTIFIER_get_arcs();
    test_object_identifier_OBJECT_IDENTIFIER_set_arcs();
}
