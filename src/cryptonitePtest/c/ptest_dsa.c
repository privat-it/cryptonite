/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "dsa.h"
#include "rs.h"

static void *speed_test_dsa_verify(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *s = NULL;
    ByteArray *r = NULL;
    ByteArray *p = ba_alloc_from_le_hex_string(
            "5b43e7bd415264166f0d3b103cd2c586e163587307dc72515c929280dac714d546e6fcda45d33005d28ae38b639b7c4933f75a342406c263010ab7990d78086fc19540247e6bf3a8aeffe8d15d4dc53f8bba988c1c27a2dda35406cd0da689049ea031b09f8f529ff225df1237e853ddb38e0880877db0fbdef0c1c91de92fb5");
    ByteArray *q = ba_alloc_from_le_hex_string("3d35c2eae18155b5a1a235243991eb777708deb4");;
    ByteArray *g = ba_alloc_from_le_hex_string(
            "523887dadcf608bcd22a05272a1f2893949197a27cb17daf9ecc1555b4e91831f293a7adaac55ec5b8a69226c56d3863c7ace3d76af2f11e99a1598d406842a1b5ac9d043429f7fbf6115ae58743bb393066a898b24b2e2431549715ec0e3ec71eb872d3968c745ec6f0d0b90c594b315d507853f66531516e00449c54fcdb47");
    ByteArray *privkey = ba_alloc_from_le_hex_string("e127aa7eb92656c57b6724dfaad394a3b90a470b");
    ByteArray *pubkey = ba_alloc_from_le_hex_string(
            "09294b3ce94075ef22250fbaa3d24da29ec5bc0f769b6fb2ba0a47ab0beb36eaf1f2d466448a3dc612c4b1ae65c50a14f25cbf9c91905df5de8e0b7b9d593730ade9a43cfbd4feb9a6527d5bc9a7a34f7338c7f09f23079bbbb575176aa11319740373277ad613f1ecf348502541565c567a95c1f51647004a9d765d00e06da2");
    DsaCtx *ctx = NULL;
    size_t byte_num;
    double time;
    double i = 0;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    byte_num = 20;
    uint8_t *data = malloc(byte_num);
    ByteArray *d = NULL;
    ByteArray *n = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;

    ASSERT_NOT_NULL(seed = ba_alloc_by_len(128));
    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = test_utils_get_prng());

    ASSERT_NOT_NULL(data_ba = ba_alloc_from_uint8(data, byte_num));
    ASSERT_RET_OK(ba_set(data_ba, 0xfa));

    ASSERT_NOT_NULL(ctx = dsa_alloc(p, q, g));
    ASSERT_RET_OK(dsa_init_sign(ctx, privkey, prng));
    ASSERT_RET_OK(dsa_sign(ctx, data_ba, &r, &s));

    i = 0;
    add_mode_name(builder, "DSA_VERIFY_1024_160");
    ASSERT_RET_OK(dsa_init_verify(ctx, pubkey));
    time = get_time();
    do {
        i++;
        ASSERT_RET_OK(dsa_verify(ctx, data_ba, r, s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, i, 0);

cleanup:
    prng_free(prng);
    BA_FREE(n, d, data_ba, r, s, g, p, q, e, seed);
    free(data);
    dsa_free(ctx);

    return NULL;
}

static void *speed_test_dsa_sign(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = NULL;
    ByteArray *s = NULL;
    ByteArray *r = NULL;
    ByteArray *p = ba_alloc_from_le_hex_string(
            "5b43e7bd415264166f0d3b103cd2c586e163587307dc72515c929280dac714d546e6fcda45d33005d28ae38b639b7c4933f75a342406c263010ab7990d78086fc19540247e6bf3a8aeffe8d15d4dc53f8bba988c1c27a2dda35406cd0da689049ea031b09f8f529ff225df1237e853ddb38e0880877db0fbdef0c1c91de92fb5");
    ByteArray *q = ba_alloc_from_le_hex_string("3d35c2eae18155b5a1a235243991eb777708deb4");;
    ByteArray *g = ba_alloc_from_le_hex_string(
            "523887dadcf608bcd22a05272a1f2893949197a27cb17daf9ecc1555b4e91831f293a7adaac55ec5b8a69226c56d3863c7ace3d76af2f11e99a1598d406842a1b5ac9d043429f7fbf6115ae58743bb393066a898b24b2e2431549715ec0e3ec71eb872d3968c745ec6f0d0b90c594b315d507853f66531516e00449c54fcdb47");
    ByteArray *privkey = ba_alloc_from_le_hex_string("e127aa7eb92656c57b6724dfaad394a3b90a470b");
    DsaCtx *ctx = NULL;
    size_t byte_num;
    double time;
    double i = 0;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    byte_num = 20;
    uint8_t *data = malloc(byte_num);
    ByteArray *d = NULL;
    ByteArray *n = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;

    ASSERT_NOT_NULL(e);
    ASSERT_NOT_NULL(seed = ba_alloc_by_len(128));
    ASSERT_RET_OK(rs_std_next_bytes(seed));
    ASSERT_NOT_NULL(prng = test_utils_get_prng());

    add_mode_name(builder, "DSA_SIGN_1024_160");
    ASSERT_NOT_NULL(data_ba = ba_alloc_from_uint8(data, byte_num));
    ASSERT_RET_OK(ba_set(data_ba, 0xfa));

    ASSERT_NOT_NULL(ctx = dsa_alloc(p, q, g));
    ASSERT_RET_OK(dsa_init_sign(ctx, privkey, prng));
    time = get_time();
    do {
        i++;
        ba_free(r);
        ba_free(s);
        ASSERT_RET_OK(dsa_sign(ctx, data_ba, &r, &s));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time (builder, i, 0);

cleanup:
    prng_free(prng);
    BA_FREE(n, d, data_ba, r, s, g, p, q, e, seed);
    free(data);
    dsa_free(ctx);

    return NULL;
}

void ptest_dsa(TableBuilder *builder)
{
    add_default_speed_measure(builder, "op\\sec");
    ptest_pthread_generator(speed_test_dsa_sign, builder);
    ptest_pthread_generator(speed_test_dsa_verify, builder);
    add_default_speed_measure(builder, "MB\\sec");
}
