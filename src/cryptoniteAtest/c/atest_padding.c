/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "paddings.h"

typedef struct {
    uint8_t block_len;
    char *data;
    char *expected;
} PaddingHelper;

static PaddingHelper pkcs7_data[] = {
        {
                16,
                "000000000000000000000000",
                "00000000000000000000000004040404",
        },
        {
                32,
                "000000000000000000000000",
                "0000000000000000000000001414141414141414141414141414141414141414",
        },
        {
                16,
                "00000000000000000000000000000000",
                "0000000000000000000000000000000010101010101010101010101010101010",
        },
        {
                1,
                "00000000000000000000000000000000",
                "0000000000000000000000000000000001",
        },
        {
                255,
                "00000000000000000000000000000000",
                "00000000000000000000000000000000EFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEF",
        },
};


void test_padding_pkcs7(PaddingHelper *td)
{
    ByteArray *data = ba_alloc_from_le_hex_string(td->data);
    ByteArray *exp = ba_alloc_from_le_hex_string(td->expected);
    ByteArray *result = NULL;
    uint8_t block_len = td->block_len;

    ASSERT_RET_OK(make_pkcs7_padding(data, block_len, &result));
    CHECK_EQUALS_BA(exp, result);

    ba_free(result);
    result = NULL;

    ASSERT_RET_OK(make_pkcs7_unpadding(exp, &result));
    CHECK_EQUALS_BA(data, result);

cleanup:

    BA_FREE(data, exp, result);
}

static PaddingHelper iso_7816_4_data[] = {
        {
                16,
                "000000000000000000000000",
                "00000000000000000000000080000000",
        },
        {
                32,
                "000000000000000000000000",
                "0000000000000000000000008000000000000000000000000000000000000000",
        },
        {
                16,
                "00000000000000000000000000000000",
                "0000000000000000000000000000000080000000000000000000000000000000",
        },
        {
                1,
                "00000000000000000000000000000000",
                "0000000000000000000000000000000080",
        },
        {
                255,
                "00000000000000000000000000000000",
                "000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
};

void test_padding_iso_7816_4(PaddingHelper *td)
{
    ByteArray *data = ba_alloc_from_le_hex_string(td->data);
    ByteArray *exp = ba_alloc_from_le_hex_string(td->expected);
    ByteArray *result = NULL;
    uint8_t block_len = td->block_len;

    ASSERT_RET_OK(make_iso_7816_4_padding(data, block_len, &result));
    CHECK_EQUALS_BA(exp, result);

    ba_free(result);
    result = NULL;

    ASSERT_RET_OK(make_iso_7816_4_unpadding(exp, &result));
    CHECK_EQUALS_BA(data, result);

cleanup:

    BA_FREE(data, exp, result);
}


void atest_padding(void)
{
    size_t err_count = error_count;

    ATEST_CORE(pkcs7_data, test_padding_pkcs7, sizeof(PaddingHelper));
    ATEST_CORE(iso_7816_4_data, test_padding_iso_7816_4, sizeof(PaddingHelper));

    if (err_count == error_count) {
        msg_print_atest("PADDING", "[pkcs7,iso7816_4]", "OK");
    } else {
        msg_print_atest("PADDING", "", "FAILED");
    }
}
