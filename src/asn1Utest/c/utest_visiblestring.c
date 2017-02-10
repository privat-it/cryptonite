/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static VisibleString_t *test_visiblestring_create(void)
{
    uint8_t encode[15] = {
        0x1a, 0x0d,
        0x54, 0x65, 0x73, 0x74,
        0x20, 0x6d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65,
        0x2e
    };

    VisibleString_t *visiblestring = NULL;

    ASN_EXECUTE(ber_decode(0, &VisibleString_desc, (void *)&visiblestring, encode, sizeof(encode)));

    ASSERT_NOT_NULL(visiblestring);
cleanup:
    return visiblestring;
}

void test_visiblestring_alloc_free(void)
{
    VisibleString_t *visiblestring = NULL;

    ASSERT_ASN_ALLOC(visiblestring);
    ASSERT_NOT_NULL(visiblestring);
cleanup:

    ASN_FREE(&VisibleString_desc, visiblestring);
}

void test_visiblestring_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[15] = {
        0x1a, 0x0d,
        0x54, 0x65, 0x73, 0x74,
        0x20, 0x6d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65,
        0x2e
    };

    VisibleString_t *visiblestring = NULL;

    visiblestring = test_visiblestring_create();
    ASSERT_NOT_NULL(visiblestring);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&VisibleString_desc, visiblestring, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&VisibleString_desc, visiblestring);
}

void test_visiblestring_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[99] = {0};
    uint8_t expected[99] = {
        0x0d,
        0xa9, 0x97, 0x9f, 0x44, 0x1b, 0x72, 0xf3, 0xe7,
        0x87, 0x3e, 0x55, 0xc0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };

    VisibleString_t *visiblestring = NULL;

    visiblestring = test_visiblestring_create();
    ASSERT_NOT_NULL(visiblestring);

    ret = uper_encode_to_buffer(&VisibleString_desc, visiblestring, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:

    ASN_FREE(&VisibleString_desc, visiblestring);
}

void test_visiblestring_uper_decode(void)
{
    uint8_t encode[99] = {
        0x0d,
        0xa9, 0x97, 0x9f, 0x44, 0x1b, 0x72, 0xf3, 0xe7,
        0x87, 0x3e, 0x55, 0xc0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00
    };

    VisibleString_t *actual = NULL;
    VisibleString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_visiblestring_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &VisibleString_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&VisibleString_desc, expected, actual));

cleanup:
    ASN_FREE(&VisibleString_desc, expected);
    ASN_FREE(&VisibleString_desc, actual);
}

void test_visiblestring_xer_decode(void)
{
    uint8_t encode[44] = {
        0x3C, 0x56, 0x69, 0x73, 0x69, 0x62, 0x6C, 0x65,
        0x53, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x3E, 0x54,
        0x65, 0x73, 0x74, 0x20, 0x6D, 0x65, 0x73, 0x73,
        0x61, 0x67, 0x65, 0x2E, 0x3C, 0x2F, 0x56, 0x69,
        0x73, 0x69, 0x62, 0x6C, 0x65, 0x53, 0x74, 0x72,
        0x69, 0x6E, 0x67, 0x3E
    };

    VisibleString_t *actual = NULL;
    VisibleString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_visiblestring_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &VisibleString_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&VisibleString_desc, expected, actual));

cleanup:
    ASN_FREE(&VisibleString_desc, expected);
    ASN_FREE(&VisibleString_desc, actual);
}

void utest_visiblestring(void)
{
    PR("%s\n", __FILE__);

    test_visiblestring_alloc_free();
    test_visiblestring_uper_encode();
    test_visiblestring_der_encode();
    test_visiblestring_uper_decode();
    test_visiblestring_xer_decode();
}
