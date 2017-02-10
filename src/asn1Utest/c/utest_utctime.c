/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest_asn1.h"

typedef struct tm tm_t;

static UTCTime_t *test_utctime_create_without_timezone(void)
{
    uint8_t encode[19] = {
        0x17, 0x11,
        0x32, 0x33, 0x30, 0x31,
        0x32, 0x35, 0x32, 0x32,
        0x30, 0x30, 0x30, 0x30,
        0x2b, 0x30, 0x32, 0x30,
        0x30
    };

    UTCTime_t *utctime = NULL;

    ASN_EXECUTE(ber_decode(0, &UTCTime_desc, (void *)&utctime, encode, sizeof(encode)));

    ASSERT_NOT_NULL(utctime);
cleanup:
    return utctime;
}

static UTCTime_t *test_utctime_create_with_timezone(void)
{
    uint8_t encode[15] = {
        0x17, 0x0d,
        0x32, 0x33, 0x30, 0x31,
        0x32, 0x35, 0x32, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x5a
    };

    UTCTime_t *utctime = NULL;

    ASN_EXECUTE(ber_decode(0, &UTCTime_desc, (void *)&utctime, encode, sizeof(encode)));

    ASSERT_NOT_NULL(utctime);
cleanup:
    return utctime;
}

void test_utctime_alloc_free(void)
{
    UTCTime_t *utctime = NULL;

    ASSERT_ASN_ALLOC(utctime);
    ASSERT_NOT_NULL(utctime);
cleanup:

    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_encode_without_timezone(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[19] = {
        0x17, 0x11,
        0x32, 0x33, 0x30, 0x31,
        0x32, 0x35, 0x32, 0x32,
        0x30, 0x30, 0x30, 0x30,
        0x2b, 0x30, 0x32, 0x30,
        0x30
    };

    UTCTime_t *utctime = NULL;

    utctime = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(utctime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&UTCTime_desc, utctime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_encode_with_timezone(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[15] = {
        0x17, 0x0d,
        0x32, 0x33, 0x30, 0x31,
        0x32, 0x35, 0x32, 0x30,
        0x30, 0x30, 0x30, 0x30,
        0x5a
    };

    UTCTime_t *utctime = NULL;

    utctime = test_utctime_create_with_timezone();
    ASSERT_NOT_NULL(utctime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&UTCTime_desc, utctime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_asn_UT2time(void)
{
    UTCTime_t *utctime = NULL;
    time_t actual;
    tm_t timeinfo = {0};
    time_t expected;

    /* UTC time 25.01.13 22:00:00 GMT. */
    timeinfo.tm_year = 123;
    timeinfo.tm_mon  = 0;
    timeinfo.tm_mday = 25;
    timeinfo.tm_hour = 22;
    timeinfo.tm_min  = 0;
    timeinfo.tm_sec  = 0;
    timeinfo.tm_isdst = -1;
    expected = mktime(&timeinfo);

    utctime = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(utctime);

    actual = asn_UT2time(utctime, NULL, 0);
    ASSERT_TRUE(actual != -1);

    ASSERT_TRUE(difftime(actual, expected) == 0);
cleanup:

    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_asn_time2UT(void)
{
    UTCTime_t *actual = NULL;
    UTCTime_t *expected = NULL;
    tm_t timeinfo = {0};

    /* UTC time 25.01.13 22:00:00 GMT. */
    timeinfo.tm_year = 123;
    timeinfo.tm_mon  = 0;
    timeinfo.tm_mday = 25;
    timeinfo.tm_hour = 22;
    timeinfo.tm_min  = 0;
    timeinfo.tm_sec  = 0;
    timeinfo.tm_isdst = -1;

    expected = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    actual = asn_time2UT(NULL, &timeinfo, false);

    ASSERT_TRUE(asn_equals(&UTCTime_desc, actual, expected));

cleanup:
    ASN_FREE(&UTCTime_desc, expected);
    ASN_FREE(&UTCTime_desc, actual);
}

void test_utctime_der_encode(void)
{
    ByteArray *actual = NULL;
    ByteArray *expected = NULL;
    uint8_t exp[19] = {
        0x17, 0x11,
        0x32, 0x33, 0x30, 0x31,
        0x32, 0x35, 0x32, 0x32,
        0x30, 0x30, 0x30, 0x30,
        0x2b, 0x30, 0x32, 0x30,
        0x30
    };

    UTCTime_t *utctime = NULL;

    utctime = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(utctime);
    ASSERT_NOT_NULL(expected = ba_alloc_from_uint8(exp, sizeof(exp)));

    ASSERT_RET_OK(asn_encode_ba(&UTCTime_desc, utctime, (void *)&actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    BA_FREE(expected, actual);
    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_uper_encode(void)
{
    asn_enc_rval_t ret;
    uint8_t actual[127] = {0};
    uint8_t expected[127] = {
        0x11,
        0x64, 0xcd, 0x83, 0x16, 0x4d, 0x59, 0x32, 0x60,
        0xc1, 0x83, 0x05, 0x6c, 0x19, 0x30, 0x60, 0x00,
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    UTCTime_t *utctime = NULL;

    utctime = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(utctime);

    ret = uper_encode_to_buffer(&UTCTime_desc, utctime, (void *)actual, sizeof(actual));
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(sizeof(expected) == ret.encoded);
    ASSERT_EQUALS(expected, actual, sizeof(expected));
cleanup:

    ASN_FREE(&UTCTime_desc, utctime);
}

void test_utctime_uper_decode(void)
{
    uint8_t encode[127] = {
        0x11,
        0x64, 0xcd, 0x83, 0x16, 0x4d, 0x59, 0x32, 0x60,
        0xc1, 0x83, 0x05, 0x6c, 0x19, 0x30, 0x60, 0x00,
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    UTCTime_t *actual = NULL;
    UTCTime_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    ret = uper_decode(0, &UTCTime_desc, (void *)&actual, encode, sizeof(encode), 0, 0);

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&UTCTime_desc, expected, actual));

cleanup:
    ASN_FREE(&UTCTime_desc, expected);
    ASN_FREE(&UTCTime_desc, actual);
}

void test_utctime_xer_decode(void)
{
    uint8_t encode[36] = {
        0x3c, 0x55, 0x54, 0x43, 0x54, 0x69, 0x6d, 0x65,
        0x3e, 0x32, 0x33, 0x30, 0x31, 0x32, 0x35, 0x32,
        0x32, 0x30, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x32,
        0x30, 0x30, 0x3c, 0x2f, 0x55, 0x54, 0x43, 0x54,
        0x69, 0x6d, 0x65, 0x3e
    };

    UTCTime_t *actual = NULL;
    UTCTime_t *expected = NULL;
    asn_dec_rval_t ret;

    expected = test_utctime_create_without_timezone();
    ASSERT_NOT_NULL(expected);

    ret = xer_decode(0, &UTCTime_desc, (void *)&actual, encode, sizeof(encode));

    ASSERT_TRUE(ret.code == RET_OK);
    ASSERT_NOT_NULL(actual);

    ASSERT_TRUE(asn_equals(&UTCTime_desc, expected, actual));

cleanup:
    ASN_FREE(&UTCTime_desc, expected);
    ASN_FREE(&UTCTime_desc, actual);
}

void utest_utctime(void)
{
    PR("%s\n", __FILE__);

    test_utctime_alloc_free();
    test_utctime_encode_without_timezone();
    test_utctime_encode_with_timezone();
    test_utctime_asn_time2UT();
    test_utctime_asn_UT2time();
    test_utctime_uper_encode();
    test_utctime_der_encode();
    test_utctime_uper_decode();
    test_utctime_xer_decode();
}
