/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static GraphicString_t *test_graphicstring_create(void)
{
    uint8_t encode[6] = {
        0x19, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    GraphicString_t *graphicstring = NULL;

    ASN_EXECUTE(ber_decode(0, &GraphicString_desc, (void *)&graphicstring, encode, sizeof(encode)));
    ASSERT_NOT_NULL(graphicstring);
cleanup:
    return graphicstring;
}

void test_graphicstring_alloc_free(void)
{
    GraphicString_t *graphicstring = NULL;

    ASSERT_ASN_ALLOC(graphicstring);
    ASSERT_NOT_NULL(graphicstring);

cleanup:

    ASN_FREE(&GraphicString_desc, graphicstring);
}

void test_graphicstring_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[6] = {
        0x19, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    GraphicString_t *graphicstring = NULL;

    graphicstring = test_graphicstring_create();
    ASSERT_NOT_NULL(graphicstring);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&GraphicString_desc, graphicstring, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(actual, expected);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&GraphicString_desc, graphicstring);
}

void test_graphicstring_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[40] = {0};
    uint8_t expected[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    GraphicString_t *graphicstring = NULL;

    graphicstring = test_graphicstring_create();
    ASSERT_NOT_NULL(graphicstring);

    ret = uper_encode_to_buffer(&GraphicString_desc, graphicstring, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

cleanup:

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));

    ASN_FREE(&GraphicString_desc, graphicstring);
}

void test_graphicstring_uper_decode(void)
{
    uint8_t encode[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    GraphicString_t *actual = NULL;
    GraphicString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_graphicstring_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &GraphicString_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    asn_equals(&GraphicString_desc, expected, actual);
cleanup:
    ASN_FREE(&GraphicString_desc, expected);
    ASN_FREE(&GraphicString_desc, actual);
}

void test_graphicstring_xer_decode(void)
{
    uint8_t encode[42] = {
        0x3c, 0x47, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63,
        0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e, 0x30,
        0x35, 0x20, 0x30, 0x36, 0x20, 0x30, 0x37, 0x20,
        0x30, 0x38, 0x3c, 0x2f, 0x47, 0x72, 0x61, 0x70,
        0x68, 0x69, 0x63, 0x53, 0x74, 0x72, 0x69, 0x6e,
        0x67, 0x3e
    };

    GraphicString_t *actual = NULL;
    GraphicString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_graphicstring_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &GraphicString_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    asn_equals(&GraphicString_desc, expected, actual);
cleanup:
    ASN_FREE(&GraphicString_desc, expected);
    ASN_FREE(&GraphicString_desc, actual);
}

void utest_graphicstring(void)
{
    PR("%s\n", __FILE__);

    test_graphicstring_alloc_free();
    test_graphicstring_encode();
    test_graphicstring_uper_encode();
    test_graphicstring_uper_decode();
    test_graphicstring_xer_decode();
}
