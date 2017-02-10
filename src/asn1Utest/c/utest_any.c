/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static const uint8_t encode[6] = {
    0x02, 0x04,
    0x05, 0x06, 0x07, 0x08
};

static ANY_t *test_any_create(void)
{
    ByteArray *encode_ba = NULL;
    ANY_t *any = NULL;

    ASSERT_NOT_NULL(encode_ba = ba_alloc_from_uint8(encode, sizeof(encode)));
    ASSERT_NOT_NULL(any = asn_decode_ba_with_alloc(&ANY_desc, encode_ba));

cleanup:
    ba_free(encode_ba);
    return any;
}

static INTEGER_t *test_integer_create(void)
{
    ByteArray *encode_ba = NULL;
    INTEGER_t *integer = NULL;

    ASSERT_NOT_NULL(encode_ba = ba_alloc_from_uint8(encode, sizeof(encode)));
    ASSERT_NOT_NULL(integer = asn_decode_ba_with_alloc(&INTEGER_desc, encode_ba));

cleanup:
    ba_free(encode_ba);
    return integer;
}

static void test_any_alloc_free(void)
{
    ANY_t *any = NULL;

    ASSERT_ASN_ALLOC(any);
    ASSERT_NOT_NULL(any);
cleanup:
    ASN_FREE(&ANY_desc, any);
}

void test_any_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    ANY_t *any = NULL;

    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(encode, sizeof(encode)));
    ASSERT_NOT_NULL(any = test_any_create());

    ASSERT_RET_OK(asn_encode_ba(&ANY_desc, any, &actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&ANY_desc, expected, actual));

cleanup:

    BA_FREE(actual, expected);
    ASN_FREE(&ANY_desc, any);
}

void test_any_ANY_fromType(void)
{
    ANY_t *expected = NULL;
    ANY_t *actual = NULL;
    INTEGER_t *integer = NULL;

    ASSERT_NOT_NULL(expected = test_any_create());

    integer = test_integer_create();
    ASSERT_NOT_NULL(integer);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(ANY_fromType(actual, &INTEGER_desc, integer));

    ASSERT_TRUE(asn_equals(&ANY_desc, expected, actual));
cleanup:
    ASN_FREE(&ANY_desc, actual);
    ASN_FREE(&ANY_desc, expected);
    ASN_FREE(&INTEGER_desc, integer);

}

void test_any_ANY_new_fromType(void)
{
    ANY_t *expected = NULL;
    ANY_t *actual = NULL;
    INTEGER_t *integer = NULL;

    ASSERT_NOT_NULL(expected = test_any_create());
    ASSERT_NOT_NULL(integer = test_integer_create());
    ASSERT_NOT_NULL(actual = ANY_new_fromType(&INTEGER_desc, integer));

    ASSERT_TRUE(asn_equals(&ANY_desc, expected, actual));
cleanup:
    ASN_FREE(&ANY_desc, actual);
    ASN_FREE(&ANY_desc, expected);
    ASN_FREE(&INTEGER_desc, integer);
}

void test_any_ANY_to_type(void)
{
    INTEGER_t *expected = NULL;
    INTEGER_t *actual = NULL;
    ANY_t *any = NULL;

    ASSERT_NOT_NULL(any = test_any_create());
    ASSERT_NOT_NULL(expected = test_integer_create());
    ASSERT_NOT_NULL(actual = asn_any2type(any, &INTEGER_desc));

    ASSERT_TRUE(asn_equals(&INTEGER_desc, expected, actual));
cleanup:
    ASN_FREE(&INTEGER_desc, actual);
    ASN_FREE(&INTEGER_desc, expected);
    ASN_FREE(&ANY_desc, any);
}

void utest_any(void)
{
    PR("%s\n", __FILE__);
    test_any_alloc_free();
    test_any_encode();
    test_any_ANY_fromType();
    test_any_ANY_new_fromType();
    test_any_ANY_to_type();
}
