/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static REAL_t *test_nativereal_create(void)
{
    uint8_t encode[11] = {
        0x09, 0x09,
        0x80, 0xd9, 0x18, 0x1c,
        0x88, 0xb0, 0x9e, 0x98,
        0xdd
    };

    REAL_t *nativereal = NULL;

    ASN_EXECUTE(ber_decode(0, &NativeReal_desc, (void *)&nativereal, encode, sizeof(encode)));

    ASSERT_NOT_NULL(nativereal);
cleanup:
    return nativereal;
}

void test_nativereal_alloc_free(void)
{
    REAL_t *nativereal = NULL;

    ASSERT_ASN_ALLOC(nativereal);
    ASSERT_NOT_NULL(nativereal);
cleanup:
    ASN_FREE(&NativeReal_desc, nativereal);
}

void test_nativereal_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[11] = {
        0x09, 0x09,
        0x80, 0xd9, 0x18, 0x1c,
        0x88, 0xb0, 0x9e, 0x98,
        0xdd
    };

    REAL_t *nativereal = NULL;

    nativereal = test_nativereal_create();
    ASSERT_NOT_NULL(nativereal);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&NativeReal_desc, nativereal, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&NativeReal_desc, nativereal);
}

void test_nativereal_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[80] = {0};
    uint8_t expected[80] = {
        0x09,
        0x80, 0xd9, 0x18, 0x1c, 0x88, 0xb0, 0x9e, 0x98,
        0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    REAL_t *nativereal = NULL;

    nativereal = test_nativereal_create();
    ASSERT_NOT_NULL(nativereal);

    ret = uper_encode_to_buffer(&NativeReal_desc, nativereal, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&NativeReal_desc, nativereal);
}

void test_nativereal_uper_decode(void)
{
    uint8_t encode[80] = {
        0x09,
        0x80, 0xd9, 0x18, 0x1c, 0x88, 0xb0, 0x9e, 0x98,
        0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    REAL_t *actual = NULL;
    REAL_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_nativereal_create();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &NativeReal_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&NativeReal_desc, expected, actual));
cleanup:
    ASN_FREE(&NativeReal_desc, expected);
    ASN_FREE(&NativeReal_desc, actual);
}

void test_nativereal_xer_decode(void)
{
    uint8_t encode[24] = {
        0x3c, 0x52, 0x45, 0x41, 0x4c, 0x3e, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x2e, 0x30, 0x36, 0x37, 0x38,
        0x39, 0x3c, 0x2f, 0x52, 0x45, 0x41, 0x4c, 0x3e
    };

    REAL_t *actual = NULL;
    REAL_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_nativereal_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &NativeReal_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&NativeReal_desc, expected, actual));
cleanup:
    ASN_FREE(&NativeReal_desc, expected);
    ASN_FREE(&NativeReal_desc, actual);
}

void utest_nativereal(void)
{
    PR("%s\n", __FILE__);

    test_nativereal_alloc_free();
    test_nativereal_uper_encode();
    test_nativereal_der_encode();
    test_nativereal_uper_decode();
    test_nativereal_xer_decode();
}
