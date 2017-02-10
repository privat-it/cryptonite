/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static uint8_t encode[7] = {
    0x03, 0x05, 0x00,
    0x05, 0x06, 0x07, 0x08
};

static BIT_STRING_t *test_bitstring_create(void)
{
    ByteArray *encode_ba = NULL;
    BIT_STRING_t *bitstring = NULL;

    ASSERT_NOT_NULL(encode_ba = ba_alloc_from_uint8(encode, sizeof(encode)));
    ASSERT_NOT_NULL(bitstring = asn_decode_ba_with_alloc(&BIT_STRING_desc, encode_ba));

cleanup:
    ba_free(encode_ba);
    return bitstring;
}

void test_bitstring_alloc_free(void)
{
    BIT_STRING_t *bitstring = NULL;

    ASSERT_ASN_ALLOC(bitstring);

cleanup:

    ASN_FREE(&BIT_STRING_desc, bitstring);
}

void test_bitstring_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    BIT_STRING_t *bitstring = NULL;

    ASSERT_NOT_NULL(bitstring = test_bitstring_create());
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(encode, sizeof(encode)));

    ASSERT_RET_OK(asn_encode_ba(&BIT_STRING_desc, bitstring, &actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&BIT_STRING_desc, bitstring);
}

void test_bitstring_asn_BITSTRING2bytes(void)
{
    size_t actual_len = 0;
    size_t expected_len = 4;
    uint8_t *actual = NULL;
    uint8_t expected[4] = {0x05, 0x06, 0x07, 0x08};

    BIT_STRING_t *bitstring = NULL;

    bitstring = test_bitstring_create();
    ASSERT_NOT_NULL(bitstring);

    ASSERT_RET_OK(asn_BITSTRING2bytes(bitstring, &actual, &actual_len));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(expected_len == actual_len);
    ASSERT_EQUALS(expected, actual, expected_len);
cleanup:
    free(actual);
    ASN_FREE(&BIT_STRING_desc, bitstring);
}

void test_bitstring_asn_bytes2BITSTRING(void)
{
    uint8_t value[4] = {0x05, 0x06, 0x07, 0x08};
    BIT_STRING_t *actual = NULL;
    BIT_STRING_t *expected = NULL;

    expected = test_bitstring_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(asn_bytes2BITSTRING(value, actual, sizeof(value)));

    ASSERT_TRUE(asn_equals(&BIT_STRING_desc, expected, actual));
cleanup:
    ASN_FREE(&BIT_STRING_desc, expected);
    ASN_FREE(&BIT_STRING_desc, actual);
}

void test_bitstring_asn_BITSTRING_get_bit(void)
{
    ByteArray *encode_ba = NULL;
    uint8_t encode[5] = {0x03, 0x03, 0x06, 0xc0, 0x80};
    BIT_STRING_t *bitstring = NULL;
    int actual;

    ASSERT_NOT_NULL(encode_ba = ba_alloc_from_uint8(encode, sizeof(encode)));
    ASSERT_NOT_NULL(bitstring = asn_decode_ba_with_alloc(&BIT_STRING_desc, encode_ba));

    ASSERT_RET_OK(asn_BITSTRING_get_bit(bitstring, 0, &actual));
    ASSERT_TRUE(actual == 1);

    ASSERT_RET_OK(asn_BITSTRING_get_bit(bitstring, 1, &actual));
    ASSERT_TRUE(actual == 1);

    ASSERT_RET_OK(asn_BITSTRING_get_bit(bitstring, 2, &actual));
    ASSERT_TRUE(actual == 0);

    ASSERT_RET_OK(asn_BITSTRING_get_bit(bitstring, 8, &actual));
    ASSERT_TRUE(actual == 1);

    ASSERT_RET_OK(asn_BITSTRING_get_bit(bitstring, 9, &actual));
    ASSERT_TRUE(actual == 0);

cleanup:
    ba_free(encode_ba);
    ASN_FREE(&BIT_STRING_desc, bitstring);
}

void utest_bitstring(void)
{
    PR("%s\n", __FILE__);

    test_bitstring_alloc_free();
    test_bitstring_encode();
    test_bitstring_asn_BITSTRING2bytes();
    test_bitstring_asn_bytes2BITSTRING();
    test_bitstring_asn_BITSTRING_get_bit();
}
