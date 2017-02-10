/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

static ENUMERATED_t *test_enumerated_create(void)
{
    uint8_t encode[] = {
        0x0a, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    ENUMERATED_t *enumerated = NULL;

    ASN_EXECUTE(ber_decode(0, &ENUMERATED_desc, (void *)&enumerated, encode, sizeof(encode)));
    ASSERT_NOT_NULL(enumerated);
cleanup:
    return enumerated;
}

void test_enumerated_alloc_free(void)
{
    ENUMERATED_t *enumerated = NULL;

    ASSERT_ASN_ALLOC(enumerated);
    ASSERT_NOT_NULL(enumerated);
cleanup:
    ASN_FREE(&ENUMERATED_desc, enumerated);
}

void test_enumerated_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[] = {
        0x0a, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    ENUMERATED_t *enumerated = NULL;

    enumerated = test_enumerated_create();
    ASSERT_NOT_NULL(enumerated);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&ENUMERATED_desc, enumerated, &actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&ENUMERATED_desc, enumerated);
}

void test_enumerated_xer_decode(void)
{
    uint8_t encode[33] = {
        0x3c, 0x45, 0x4e, 0x55, 0x4d, 0x45, 0x52, 0x41,
        0x54, 0x45, 0x44, 0x3e, 0x31, 0x36, 0x39, 0x30,
        0x39, 0x30, 0x36, 0x30, 0x3c, 0x2f, 0x45, 0x4e,
        0x55, 0x4d, 0x45, 0x52, 0x41, 0x54, 0x45, 0x44,
        0x3e
    };

    ENUMERATED_t *actual = NULL;
    ENUMERATED_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_enumerated_create();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &ENUMERATED_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&ENUMERATED_desc, expected, actual));
cleanup:

    ASN_FREE(&ENUMERATED_desc, expected);
    ASN_FREE(&ENUMERATED_desc, actual);
}

void utest_enumerated(void)
{
    PR("%s\n", __FILE__);

    test_enumerated_alloc_free();
    test_enumerated_encode();
    test_enumerated_xer_decode();
}
