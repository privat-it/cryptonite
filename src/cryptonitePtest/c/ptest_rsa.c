/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>

#include "ptest.h"
#include "rsa.h"

void *speed_test_rsa_sign(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *data_ba = ba_alloc_by_len(20);
    ByteArray *dec = NULL;
    RsaCtx *ctx = NULL;
    size_t byte_num;
    double time;
    size_t i = 0;
    byte_num = 20;
    uint8_t *data = calloc(1, byte_num);
    ByteArray *n = ba_alloc_from_le_hex_string(
            "b571c4975d5ebfdf262412f80c23f84676550f838fcd70911cc3e23cbbe8e2e71c33dddda4a4502ce65f5cd17537f86b91f9de0c2f1fa84de6013264857cbc6685c93bda96b7e25900127554d3c294b8c97825c09efdfdb3e53dfa6caa7f1ad107bad90b76f7a13c502a81660c4e37ce1bbc1457b6bf378473fef7a70091f030");
    ByteArray *d = ba_alloc_from_le_hex_string(
            "6b3ca8fc50ecd52ad2b2db6cf5073720443ffe18a6e86b2e733a858e52729f66059d93c21fbee220ce3c506f1ec2dca5838222d7a226e54ffa2acd165915c70203317d91647aec3b000c4e38e281b82531fb188014a9fe77eed3a6481c55bce0af2691b24efa6b28e0c600efb2de2434bdd20d3a24d5cf024d54a51aab60a020");
    PrngCtx *prng = NULL;

    add_mode_name(builder, "RSA_SIGN_1024");

    ctx = rsa_alloc();

    ba_set(data_ba, 0x80);
    rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, d);
    time = get_time();
    do {
        i++;
        ba_free(dec);
        rsa_sign_pkcs1_v1_5(ctx, data_ba, &dec);
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, (double)i, 0);

    prng_free(prng);
    BA_FREE(n, d, data_ba, dec);
    free(data);
    rsa_free(ctx);

    return NULL;
}

void *speed_test_rsa_verify(void *void_builder)
{
    TableBuilder *builder = (TableBuilder *) void_builder;
    ByteArray *sign_expected =
            ba_alloc_from_be_hex_string("28928e19eb86f9c00070a59edf6bf8433a45df495cd1c73613c2129840f48c4a"
                    "2c24f11df79bc5c0782bcedde97dbbb2acc6e512d19f085027cd575038453d04"
                    "905413e947e6e1dddbeb3535cdb3d8971fe0200506941056f21243503c83eadd"
                    "e053ed866c0e0250beddd927a08212aa8ac0efd61631ef89d8d049efb36bb35f");

    ByteArray *n =
            ba_alloc_from_be_hex_string("c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2b"
                    "c59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b"
                    "2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15"
                    "397183fbf1f0353c9fc991");
    ByteArray *e =
            ba_alloc_from_be_hex_string("000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    "0000000000000000010001");
    ByteArray *hash = ba_alloc_from_le_hex_string("c8919f9087282f2059f112b55faae3c6462f4469");
    RsaCtx *ctx = NULL;
    size_t i = 0;
    double time;

    add_mode_name(builder, "RSA_VERIFY_1024");

    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, e));

    time = get_time();
    do {
        i++;
        ASSERT_RET_OK(rsa_verify_pkcs1_v1_5(ctx, hash, sign_expected));
    } while (((get_time() - time) / DEFAULT_CLOCKS_PS_VALUE) < 1);
    add_time(builder, (double)i, 0);

cleanup:

    BA_FREE(e, n, sign_expected, hash);
    rsa_free(ctx);

    return NULL;
}


void ptest_rsa(TableBuilder *builder)
{
    add_default_speed_measure(builder, OP_STRING_VALUE);
    ptest_pthread_generator(speed_test_rsa_sign, builder);
    ptest_pthread_generator(speed_test_rsa_verify, builder);
    add_default_speed_measure(builder, MB_STRING_VALUE);
}
