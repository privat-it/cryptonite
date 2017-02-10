/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static PrintableString_t *test_printablestring_create(void)
{
    uint8_t encode[15] = {
        0x13, 0x0d,
        0x54, 0x65, 0x73, 0x74,
        0x20, 0x6d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65,
        0x2e
    };

    PrintableString_t *printablestring = NULL;

    ASN_EXECUTE(ber_decode(0, &PrintableString_desc, (void *)&printablestring, encode, sizeof(encode)));

    ASSERT_NOT_NULL(printablestring);
cleanup:
    return printablestring;
}

void test_printablestring_alloc_free(void)
{
    PrintableString_t *printablestring = NULL;

    ASSERT_ASN_ALLOC(printablestring);
    ASSERT_NOT_NULL(printablestring);
cleanup:

    ASN_FREE(&PrintableString_desc, printablestring);
}

void test_printablestring_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[15] = {
        0x13, 0x0d,
        0x54, 0x65, 0x73, 0x74,
        0x20, 0x6d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65,
        0x2e
    };

    PrintableString_t *printablestring = NULL;

    printablestring = test_printablestring_create();
    ASSERT_NOT_NULL(printablestring);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&PrintableString_desc, printablestring, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&PrintableString_desc, printablestring);
}

void test_printablestring_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[60] = {0};
    uint8_t expected[60] = {
        0x0d,
        0x94, 0x23, 0x0c, 0x42, 0x20, 0x64, 0x70, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    PrintableString_t *printablestring = NULL;

    printablestring = test_printablestring_create();
    ASSERT_NOT_NULL(printablestring);

    ret = uper_encode_to_buffer(&PrintableString_desc, printablestring, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:

    ASN_FREE(&PrintableString_desc, printablestring);
}

void test_printablestring_uper_decode(void)
{
    uint8_t encode[60] = {
        0x0d,
        0xa9, 0x97, 0x9f, 0x44, 0x1b, 0x72, 0xf3, 0xe7,
        0x87, 0x3e, 0x55, 0xc0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    PrintableString_t *actual = NULL;
    PrintableString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_printablestring_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &PrintableString_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&PrintableString_desc, expected, actual));

cleanup:
    ASN_FREE(&PrintableString_desc, expected);
    ASN_FREE(&PrintableString_desc, actual);
}

void test_printablestring_xer_decode(void)
{
    uint8_t encode[48] = {
        0x3c, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x61, 0x62,
        0x6c, 0x65, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
        0x3e, 0x54, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65,
        0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x3c, 0x2f,
        0x50, 0x72, 0x69, 0x6e, 0x74, 0x61, 0x62, 0x6c,
        0x65, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3e
    };

    PrintableString_t *actual = NULL;
    PrintableString_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_printablestring_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &PrintableString_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&PrintableString_desc, expected, actual));

cleanup:
    ASN_FREE(&PrintableString_desc, expected);
    ASN_FREE(&PrintableString_desc, actual);
}

void utest_printablestring(void)
{
    PR("%s\n", __FILE__);

    test_printablestring_alloc_free();
    test_printablestring_uper_encode();
    test_printablestring_der_encode();
    test_printablestring_xer_decode();
}
