/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static ENUMERATED_t *test_nativeenumerated_create(void)
{
    uint8_t encode[3] = {0x0a, 0x01, 0x02};

    ENUMERATED_t *nativeenumerated = NULL;

    ASN_EXECUTE(ber_decode(0, &NativeEnumerated_desc, (void *)&nativeenumerated, encode, sizeof(encode)));

    ASSERT_NOT_NULL(nativeenumerated);
cleanup:
    return nativeenumerated;
}

void test_nativeenumerated_alloc_free(void)
{
    ENUMERATED_t *nativeenumerated = NULL;

    ASSERT_ASN_ALLOC(nativeenumerated);
    ASSERT_NOT_NULL(nativeenumerated);
cleanup:
    ASN_FREE(&NativeEnumerated_desc, nativeenumerated);
}

void test_nativeenumerated_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[3] = {0x0a, 0x01, 0x02};

    ENUMERATED_t *nativeenumerated = NULL;

    nativeenumerated = test_nativeenumerated_create();
    ASSERT_NOT_NULL(nativeenumerated);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&NativeEnumerated_desc, nativeenumerated, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(actual, expected);
    ASN_FREE(&NativeEnumerated_desc, nativeenumerated);
}

void test_nativeenumerated_xer_decode(void)
{
    uint8_t encode[26] = {
        0x3c, 0x45, 0x4e, 0x55, 0x4d, 0x45, 0x52, 0x41,
        0x54, 0x45, 0x44, 0x3e, 0x32, 0x3c, 0x2f, 0x45,
        0x4e, 0x55, 0x4d, 0x45, 0x52, 0x41, 0x54, 0x45,
        0x44, 0x3e
    };

    ENUMERATED_t *actual = NULL;
    ENUMERATED_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_nativeenumerated_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &NativeEnumerated_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&NativeEnumerated_desc, expected, actual));
cleanup:
    ASN_FREE(&NativeEnumerated_desc, expected);
    ASN_FREE(&NativeEnumerated_desc, actual);
}


void utest_nativeenumerated(void)
{
    PR("%s\n", __FILE__);

    test_nativeenumerated_alloc_free();
    test_nativeenumerated_der_encode();
    test_nativeenumerated_xer_decode();
}
