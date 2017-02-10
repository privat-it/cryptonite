/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "ecdsa.h"

static void *speed_test_ecdsa_sign(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    EcdsaCtx *ctx = NULL;
    size_t byte_num;
    double time;
    size_t i = 0;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    byte_num = 20;
    uint8_t *data = malloc(byte_num);
    ByteArray *d = NULL;
    ByteArray *n = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    add_mode_name(builder, "ECDSA_SIGN_P192_R1");
    ASSERT_NOT_NULL(data_ba = ba_alloc_from_uint8(data, byte_num));
    ASSERT_RET_OK(ba_set(data_ba, 0xfa));
    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_RET_OK(ecdsa_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(ecdsa_generate_privkey(ctx, prng, &d));
    ASSERT_RET_OK(ecdsa_get_pubkey(ctx, d, &qx, &qy));
    ASSERT_RET_OK(ecdsa_init_sign(ctx, d, prng));
    time = get_time();
    do {
        i++;
        ba_free(r);
        ba_free(s);
        ASSERT_RET_OK(ecdsa_sign(ctx, data_ba, &r, &s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time (builder, (double)i, 0);

cleanup:
    prng_free(prng);
    BA_FREE(n, d, data_ba, r, s, qx, qy, e);
    free(data);
    ecdsa_free(ctx);

    return NULL;
}

static void *speed_test_ecdsa_verify(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *qx = ba_alloc_from_be_hex_string("8CF149E91FDFE308B66FAD9F82BBB098576FEA6BEACA7377");
    ByteArray *qy = ba_alloc_from_be_hex_string("AB6F6331C39C220BEA716E93722217FFFE727A962402C66D");
    ByteArray *hash = ba_alloc_from_le_hex_string("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ByteArray *r = ba_alloc_from_be_hex_string("D693C651109B4EDE0FDAB92779F74D5D8965A16C5881BEED");
    ByteArray *s = ba_alloc_from_be_hex_string("5BF193AD07A2FE10EEDD70D43A9B14404E3C284907825407");
    EcdsaCtx *ctx = NULL;
    double time;
    add_mode_name(builder, "ECDSA_VERIFY_P192_R1");
    size_t i = 0;

    ASSERT_NOT_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P192_R1));
    ASSERT_RET_OK(ecdsa_set_opt_level(ctx, OPT_LEVEL_COMB_11_COMB_11));
    ASSERT_RET_OK(ecdsa_init_verify(ctx, qx, qy));
    time = get_time();
    do {
        i++;
        ASSERT_RET_OK(ecdsa_verify(ctx, hash, r, s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);

    add_time(builder, (double)i, 0);

cleanup:
    BA_FREE(qx, qy, hash, r, s);

    ecdsa_free(ctx);

    return NULL;
}

void ptest_ecdsa(TableBuilder *builder)
{
    add_default_speed_measure(builder, OP_STRING_VALUE);
    ptest_pthread_generator(speed_test_ecdsa_sign, builder);
    ptest_pthread_generator(speed_test_ecdsa_verify, builder);
    add_default_speed_measure(builder, MB_STRING_VALUE);
}
