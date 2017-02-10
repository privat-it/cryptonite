/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static NumericString_t *test_numericstring_create(void)
{
    uint8_t encode[12] = {
        0x12, 0x0a,
        0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38,
        0x39, 0x30
    };

    NumericString_t *numericstring = NULL;

    ASN_EXECUTE(ber_decode(0, &NumericString_desc, (void *)&numericstring, encode, sizeof(encode)));

    ASSERT_NOT_NULL(numericstring);
cleanup:
    return numericstring;
}

void test_numericstring_alloc_free(void)
{
    NumericString_t *numericstring = NULL;

    ASSERT_ASN_ALLOC(numericstring);
    ASSERT_NOT_NULL(numericstring);
cleanup:
    ASN_FREE(&NumericString_desc, numericstring);
}

void test_numericstring_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[12] = {
        0x12, 0x0a,
        0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38,
        0x39, 0x30
    };

    NumericString_t *numericstring = NULL;

    numericstring = test_numericstring_create();
    ASSERT_NOT_NULL(numericstring);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&NumericString_desc, numericstring, (void *)&actual));
    ASSERT_NOT_NULL(actual);
    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&NumericString_desc, numericstring);
}

void test_numericstring_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[48] = {0};
    uint8_t expected[48] = {
        0x0a,
        0x23, 0x45, 0x67, 0x89, 0xa1, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    NumericString_t *numericstring = NULL;

    numericstring = test_numericstring_create();
    ASSERT_NOT_NULL(numericstring);

    ret = uper_encode_to_buffer(&NumericString_desc, numericstring, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&NumericString_desc, numericstring);
}

void test_numericstring_uper_decode(void)
{
    uint8_t encode[48] = {
        0x0a,
        0x23, 0x45, 0x67, 0x89, 0xa1, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    NumericString_t *actual = NULL;
    NumericString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_numericstring_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &NumericString_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&NumericString_desc, expected, actual));

cleanup:
    ASN_FREE(&NumericString_desc, expected);
    ASN_FREE(&NumericString_desc, actual);
}

void test_numericstring_xer_decode(void)
{
    uint8_t encode[41] = {
        0x3c, 0x4e, 0x75, 0x6d, 0x65, 0x72, 0x69, 0x63,
        0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x3c, 0x2f, 0x4e, 0x75, 0x6d, 0x65, 0x72,
        0x69, 0x63, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
        0x3e
    };

    NumericString_t *actual = NULL;
    NumericString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_numericstring_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &NumericString_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&NumericString_desc, expected, actual));

cleanup:
    ASN_FREE(&NumericString_desc, expected);
    ASN_FREE(&NumericString_desc, actual);
}

void utest_numericstring(void)
{
    PR("%s\n", __FILE__);

    test_numericstring_alloc_free();
    test_numericstring_uper_encode();
    test_numericstring_der_encode();
    test_numericstring_uper_decode();
    test_numericstring_xer_decode();
}
