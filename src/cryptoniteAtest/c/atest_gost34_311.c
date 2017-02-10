/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "hmac.h"

void test_hmac_gost3411(void)
{
    ByteArray *sync = ba_alloc_from_le_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    ByteArray *data1 = ba_alloc_from_le_hex_string("31a58dc1462981189cf6c701e276c755");
    ByteArray *data2 = ba_alloc_from_le_hex_string("3a5ab5f6e36d8418e4aa40c930cf3876");
    ByteArray *key = ba_alloc_from_le_hex_string("70617373776f7264");
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "482e7ae77f7607584c883961770fb374bd85062a1970df77a847c3f9c18ea9a0");
    ByteArray *actual = NULL;
    HmacCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, sync));
    ASSERT_RET_OK(hmac_init(ctx, key));
    ASSERT_RET_OK(hmac_update(ctx, data1));
    ASSERT_RET_OK(hmac_update(ctx, data2));
    ASSERT_RET_OK(hmac_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(sync, data1, data2, key, expected, actual);
    hmac_free(ctx);
}


void atest_gost34_311(void)
{
    size_t err_count = error_count;

    test_hmac_gost3411();

    if (err_count == error_count) {
        msg_print_atest("GOST34_311", "[hmac]", "OK");
    } else {
        msg_print_atest("GOST34_311", "", "FAILED");
    }
}
