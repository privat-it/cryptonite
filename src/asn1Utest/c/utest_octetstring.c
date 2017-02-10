/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static OCTET_STRING_t *test_octetstring_create(void)
{
    uint8_t encode[6] = {
        0x04, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    OCTET_STRING_t *octetstring = NULL;

    ASN_EXECUTE(ber_decode(0, &OCTET_STRING_desc, (void *)&octetstring, encode, sizeof(encode)));

    ASSERT_NOT_NULL(octetstring);
cleanup:
    return octetstring;
}

void test_octetstring_alloc_free(void)
{
    OCTET_STRING_t *octetstring = NULL;


    ASSERT_ASN_ALLOC(octetstring);
    ASSERT_NOT_NULL(octetstring);
cleanup:

    ASN_FREE(&OCTET_STRING_desc, octetstring);
}

void test_octetstring_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[6] = {
        0x04, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    OCTET_STRING_t *octetstring = NULL;

    octetstring = test_octetstring_create();
    ASSERT_NOT_NULL(octetstring);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&OCTET_STRING_desc, octetstring, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&OCTET_STRING_desc, octetstring);
}

void test_octetstring_uper_encode(void)
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

    OCTET_STRING_t *octetstring = NULL;

    octetstring = test_octetstring_create();
    ASSERT_NOT_NULL(octetstring);

    ret = uper_encode_to_buffer(&OCTET_STRING_desc, octetstring, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:

    ASN_FREE(&OCTET_STRING_desc, octetstring);
}

void test_octetstring_uper_decode(void)
{
    uint8_t encode[40] = {
        0x04,
        0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00
    };

    OCTET_STRING_t *actual = NULL;
    OCTET_STRING_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_octetstring_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &OCTET_STRING_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&OCTET_STRING_desc, expected, actual));

cleanup:
    ASN_FREE(&OCTET_STRING_desc, expected);
    ASN_FREE(&OCTET_STRING_desc, actual);
}

void test_octetstring_xer_decode(void)
{
    uint8_t encode[40] = {
        0x3c, 0x4f, 0x43, 0x54, 0x45, 0x54, 0x5f, 0x53,
        0x54, 0x52, 0x49, 0x4e, 0x47, 0x3e, 0x30, 0x35,
        0x20, 0x30, 0x36, 0x20, 0x30, 0x37, 0x20, 0x30,
        0x38, 0x3c, 0x2f, 0x4f, 0x43, 0x54, 0x45, 0x54,
        0x5f, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x3e
    };

    OCTET_STRING_t *actual = NULL;
    OCTET_STRING_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_octetstring_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &OCTET_STRING_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&OCTET_STRING_desc, expected, actual));

cleanup:
    ASN_FREE(&OCTET_STRING_desc, expected);
    ASN_FREE(&OCTET_STRING_desc, actual);
}

void test_octetstring_asn_OCTSTRING2bytes(void)
{
    size_t actual_len = 0;
    size_t expected_len = 4;
    uint8_t *actual = NULL;
    uint8_t expected[4] = {0x05, 0x06, 0x07, 0x08};

    OCTET_STRING_t *octetstring = NULL;

    octetstring = test_octetstring_create();
    ASSERT_NOT_NULL(octetstring);

    ASSERT_RET_OK(asn_OCTSTRING2bytes(octetstring, &actual, &actual_len));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(expected_len == actual_len);
    ASSERT_EQUALS(expected, actual, expected_len);

cleanup:
    free(actual);
    ASN_FREE(&OCTET_STRING_desc, octetstring);
}

void test_octetstring_asn_bytes2OCTSTRING(void)
{
    uint8_t value[4] = {0x05, 0x06, 0x07, 0x08};
    OCTET_STRING_t *actual = NULL;
    OCTET_STRING_t *expected = NULL;

    expected = test_octetstring_create();
    ASSERT_NOT_NULL(expected);

    ASSERT_ASN_ALLOC(actual);
    ASSERT_NOT_NULL(actual);

    ASSERT_RET_OK(asn_bytes2OCTSTRING(actual, value, sizeof(value)));

    ASSERT_TRUE(asn_equals(&OCTET_STRING_desc, expected, actual));

cleanup:
    ASN_FREE(&OCTET_STRING_desc, expected);
    ASN_FREE(&OCTET_STRING_desc, actual);
}

void utest_octetstring(void)
{
    PR("%s\n", __FILE__);

    test_octetstring_alloc_free();
    test_octetstring_uper_encode();
    test_octetstring_der_encode();
    test_octetstring_uper_decode();
    test_octetstring_xer_decode();
    test_octetstring_asn_OCTSTRING2bytes();
    test_octetstring_asn_bytes2OCTSTRING();
}
