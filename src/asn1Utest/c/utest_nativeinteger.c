/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static INTEGER_t *test_nativeinteger_create(void)
{
    uint8_t encode[6] = {
        0x02, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    INTEGER_t *nativeinteger = NULL;

    ASN_EXECUTE(ber_decode(0, &NativeInteger_desc, (void *)&nativeinteger, encode, sizeof(encode)));

    ASSERT_NOT_NULL(nativeinteger);
cleanup:
    return nativeinteger;
}

void test_nativeinteger_alloc_free(void)
{
    INTEGER_t *nativeinteger = NULL;

    ASSERT_ASN_ALLOC(nativeinteger);
    ASSERT_NOT_NULL(nativeinteger);
cleanup:
    ASN_FREE(&NativeInteger_desc, nativeinteger);
}

void test_nativeinteger_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[6] = {
        0x02, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    INTEGER_t *nativeinteger = NULL;

    nativeinteger = test_nativeinteger_create();
    ASSERT_NOT_NULL(nativeinteger);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&NativeInteger_desc, nativeinteger, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&NativeInteger_desc, nativeinteger);
}

void utest_nativeinteger(void)
{
    PR("%s\n", __FILE__);

    test_nativeinteger_alloc_free();
    test_nativeinteger_encode();
}
