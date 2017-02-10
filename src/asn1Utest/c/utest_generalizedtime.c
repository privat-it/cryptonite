/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

typedef struct tm tm_t;

static GeneralizedTime_t *test_generalizedtime_create_without_timezone(void)
{
    /* GeneralizedTime 2013-01-25 20:00:00 UTC */
    uint8_t encode[21] = {
        0x18, 0x13,
        0x32, 0x30, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x35,
        0x32, 0x32, 0x30, 0x30,
        0x30, 0x30, 0x2b, 0x30,
        0x32, 0x30, 0x30
    };

    GeneralizedTime_t *generalizedtime = NULL;

    ASN_EXECUTE(ber_decode(0, &GeneralizedTime_desc, (void *)&generalizedtime, encode, sizeof(encode)));
    ASSERT_NOT_NULL(generalizedtime);
cleanup:
    return generalizedtime;
}

static GeneralizedTime_t *test_generalizedtime_create_with_timezone(void)
{
    /* GeneralizedTime 2023-01-25 20:00:00 UTC */
    uint8_t encode[17] = {
        0x18, 0x0f,
        0x32, 0x30, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x35,
        0x32, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x5a
    };

    GeneralizedTime_t *generalizedtime = NULL;

    ASN_EXECUTE(ber_decode(0, &GeneralizedTime_desc, (void *)&generalizedtime, encode, sizeof(encode)));

    ASSERT_NOT_NULL(generalizedtime);
cleanup:
    return generalizedtime;
}

void test_generalizedtime_alloc_free(void)
{
    GeneralizedTime_t *generalizedtime = NULL;

    ASSERT_ASN_ALLOC(generalizedtime);
    ASSERT_NOT_NULL(generalizedtime);
cleanup:
    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_encode_without_timezone(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[21] = {
        0x18, 0x13,
        0x32, 0x30, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x35,
        0x32, 0x32, 0x30, 0x30,
        0x30, 0x30, 0x2b, 0x30,
        0x32, 0x30, 0x30
    };

    GeneralizedTime_t *generalizedtime = NULL;

    generalizedtime = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(generalizedtime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&GeneralizedTime_desc, generalizedtime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_encode_with_timezone(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[17] = {
        0x18, 0x0f,
        0x32, 0x30, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x35,
        0x32, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x5a
    };

    GeneralizedTime_t *generalizedtime = NULL;

    generalizedtime = test_generalizedtime_create_with_timezone();
    ASSERT_NOT_NULL(generalizedtime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&GeneralizedTime_desc, generalizedtime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_asn_GT2time(void)
{
    GeneralizedTime_t *generalizedtime = NULL;
    time_t actual;
    tm_t timeinfo;
    time_t expected;

    /* UTC time 25.01.23 22:00:00 GMT. */
    timeinfo.tm_year = 2023 - 1900;
    timeinfo.tm_mon  = 0;
    timeinfo.tm_mday = 25;
    timeinfo.tm_hour = 22;
    timeinfo.tm_min  = 0;
    timeinfo.tm_sec  = 0;
    timeinfo.tm_isdst = -1;
    expected = mktime(&timeinfo);

    generalizedtime = test_generalizedtime_create_with_timezone();
    ASSERT_NOT_NULL(generalizedtime);

    actual = asn_GT2time(generalizedtime, NULL, 0);
    ASSERT_TRUE(actual != -1);

    ASSERT_TRUE(difftime(actual, expected) == 0);

cleanup:

    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_asn_time2GT(void)
{
    GeneralizedTime_t *actual = NULL;
    GeneralizedTime_t *expected = NULL;
    tm_t timeinfo = {0};

    /* UTC time 25.01.13 22:00:00 GMT. */
    timeinfo.tm_year = 123;
    timeinfo.tm_mon  = 0;
    timeinfo.tm_mday = 25;
    timeinfo.tm_hour = 22;
    timeinfo.tm_min  = 0;
    timeinfo.tm_sec  = 0;
    timeinfo.tm_isdst = -1;

    expected = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    actual = asn_time2GT(NULL, &timeinfo, false);

    ASSERT_TRUE(asn_equals(&GeneralizedTime_desc, expected, actual));

cleanup:

    ASN_FREE(&GeneralizedTime_desc, expected);
    ASN_FREE(&GeneralizedTime_desc, actual);
}

void test_generalizedtime_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[21] = {
        0x18, 0x13,
        0x32, 0x30, 0x32, 0x33,
        0x30, 0x31, 0x32, 0x35,
        0x32, 0x32, 0x30, 0x30,
        0x30, 0x30, 0x2b, 0x30,
        0x32, 0x30, 0x30
    };

    GeneralizedTime_t *generalizedtime = NULL;

    generalizedtime = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(generalizedtime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));
    ASSERT_RET_OK(asn_encode_ba(&GeneralizedTime_desc, generalizedtime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(actual, expected);
    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[141] = {0};
    uint8_t expected[141] = {
        0x13,
        0x64, 0xc1, 0x93, 0x36, 0x0c, 0x59, 0x35, 0x64,
        0xc9, 0x83, 0x06, 0x0c, 0x15, 0xb0, 0x64, 0xc1,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    GeneralizedTime_t *generalizedtime = NULL;

    generalizedtime = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(generalizedtime);

    ret = uper_encode_to_buffer(&GeneralizedTime_desc, generalizedtime, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:
    ASN_FREE(&GeneralizedTime_desc, generalizedtime);
}

void test_generalizedtime_uper_decode(void)
{
    uint8_t encode[141] = {
        0x13,
        0x64, 0xc1, 0x93, 0x36, 0x0c, 0x59, 0x35, 0x64,
        0xc9, 0x83, 0x06, 0x0c, 0x15, 0xb0, 0x64, 0xc1,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    GeneralizedTime_t *actual = NULL;
    GeneralizedTime_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &GeneralizedTime_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&GeneralizedTime_desc, expected, actual));
cleanup:
    ASN_FREE(&GeneralizedTime_desc, expected);
    ASN_FREE(&GeneralizedTime_desc, actual);
}

void test_generalizedtime_xer_decode(void)
{
    uint8_t encode[54] = {
        0x3c, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
        0x69, 0x7a, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65,
        0x3e, 0x32, 0x30, 0x32, 0x33, 0x30, 0x31, 0x32,
        0x35, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x2b,
        0x30, 0x32, 0x30, 0x30, 0x3c, 0x2f, 0x47, 0x65,
        0x6e, 0x65, 0x72, 0x61, 0x6c, 0x69, 0x7a, 0x65,
        0x64, 0x54, 0x69, 0x6d, 0x65, 0x3e
    };

    GeneralizedTime_t *actual = NULL;
    GeneralizedTime_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_generalizedtime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &GeneralizedTime_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&GeneralizedTime_desc, expected, actual));
cleanup:
    ASN_FREE(&GeneralizedTime_desc, expected);
    ASN_FREE(&GeneralizedTime_desc, actual);
}

void utest_generalizedtime(void)
{
    PR("%s\n", __FILE__);

    test_generalizedtime_alloc_free();
    test_generalizedtime_encode_without_timezone();
    test_generalizedtime_encode_with_timezone();
    test_generalizedtime_asn_GT2time();
    test_generalizedtime_asn_time2GT();
    test_generalizedtime_uper_encode();
    test_generalizedtime_der_encode();
    test_generalizedtime_uper_decode();
    test_generalizedtime_xer_decode();
}
