/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "rsa.h"
#include "rs.h"

static void test_rsa_sign(void)
{
    ByteArray *sign_expected =
            ba_alloc_from_be_hex_string("28928e19eb86f9c00070a59edf6bf8433a45df495cd1c73613c2129840f48c4a"
                    "2c24f11df79bc5c0782bcedde97dbbb2acc6e512d19f085027cd575038453d04"
                    "905413e947e6e1dddbeb3535cdb3d8971fe0200506941056f21243503c83eadd"
                    "e053ed866c0e0250beddd927a08212aa8ac0efd61631ef89d8d049efb36bb35f");
    ByteArray *d =
            ba_alloc_from_be_hex_string("5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37"
                    "a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c01"
                    "89d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010a"
                    "c51a7799b1ff8483644a3d425");
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
    ByteArray *sign = NULL;
    RsaCtx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, d));
    ASSERT_RET_OK(rsa_sign_pkcs1_v1_5(ctx, hash, &sign));
    ASSERT_EQUALS_BA(sign_expected, sign);

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, e));
    ASSERT_RET_OK(rsa_verify_pkcs1_v1_5(ctx, hash, sign));

cleanup:

    BA_FREE(e, d, n, sign_expected, hash, sign);
    rsa_free(ctx);
}

static void test_rsa_sign2(void)
{
    ByteArray *hash = ba_alloc_from_le_hex_string("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898");
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    ByteArray *n = ba_alloc_from_le_hex_string(
            "ab5eec8429d4a421c4a9dc7d675c844c8a82e2e5dc213801e14730c6bc34c33d2ac4896608a7e38f6767392caff96b3cf24a86d5748f9c379ee247900eb0a831");
    ByteArray *d = ba_alloc_from_le_hex_string(
            "8b6b48c9abc99b8f304ec0eb92136be53228968e0e2b260487c94ffe6d4537631bd85b44b0c4970a459a7b1dcafb47284c87598ef8b4bdcfbe4185b509201b21");
    ByteArray *sign = NULL;
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA256, n, d));
    ASSERT_RET_OK(rsa_sign_pkcs1_v1_5(ctx, hash, &sign));

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA256, n, e));
    ASSERT_RET_OK(rsa_verify_pkcs1_v1_5(ctx, hash, sign));

cleanup:

    prng_free(prng);
    rsa_free(ctx);
    BA_FREE(e, d, n, hash, sign);
}

static void test_rsa_sign3(void)
{
    ByteArray *hash =
            ba_alloc_from_le_hex_string("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *d = ba_alloc_from_be_hex_string(
            "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425");
    ByteArray *n = ba_alloc_from_be_hex_string(
            "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
    ByteArray *e = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    ByteArray *sign = NULL;
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA384, n, d));
    ASSERT_RET_OK(rsa_sign_pkcs1_v1_5(ctx, hash, &sign));

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA384, n, e));
    ASSERT_RET_OK(rsa_verify_pkcs1_v1_5(ctx, hash, sign));

cleanup:

    prng_free(prng);
    rsa_free(ctx);
    BA_FREE(e, d, n, hash, sign);
}

static void test_rsa_sign4(void)
{
    ByteArray *hash =
            ba_alloc_from_le_hex_string("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    ByteArray *d = ba_alloc_from_be_hex_string(
            "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425");
    ByteArray *n = ba_alloc_from_be_hex_string(
            "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
    ByteArray *e = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    ByteArray *sign = NULL;
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA512, n, d));
    ASSERT_RET_OK(rsa_sign_pkcs1_v1_5(ctx, hash, &sign));

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA512, n, e));
    ASSERT_RET_OK(rsa_verify_pkcs1_v1_5(ctx, hash, sign));

cleanup:

    prng_free(prng);
    rsa_free(ctx);
    BA_FREE(e, d, n, hash, sign);
}

static void test_rsa_sign5_hash_len_is_not_valid(void)
{
    ByteArray *hash = ba_alloc_from_le_hex_string("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898");
    ByteArray *d = ba_alloc_from_be_hex_string(
            "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425");
    ByteArray *n = ba_alloc_from_be_hex_string(
            "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
    ByteArray *e = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    ByteArray *sign = NULL;
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA384, n, d));
    rsa_sign_pkcs1_v1_5(ctx, hash, &sign);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_HASH_LEN);

    ASSERT_RET_OK(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA384, n, e));
    rsa_verify_pkcs1_v1_5(ctx, hash, sign);
    err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:

    prng_free(prng);
    rsa_free(ctx);
    BA_FREE(e, d, n, hash, sign);
}

static void test_rsa_oaep_SHA1(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *n = ba_alloc_from_le_hex_string(
            "5f7e4cc092b7d3a830d2000290d8bf175bdddeee82b03ea8d392fcf291602f2c95be8ebe6fc30ccb765facf86cfc5d9dd887aef7ae04e9c5c5855c5fd3a50434");
    ByteArray *d = ba_alloc_from_le_hex_string(
            "6bccbaa912210494fd1a44cec5136f046c0c0a045bac895a3cbd2bccec5e647d0d7fb429f52cb3dcf9941dfb9dfd93133b051fa574589b2ed903933fe2c3ad22");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA1, NULL, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA1, NULL, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted);
    rsa_free(ctx);
}

static void test_rsa_pkcs1_v1_5(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *n = ba_alloc_from_le_hex_string(
            "5f7e4cc092b7d3a830d2000290d8bf175bdddeee82b03ea8d392fcf291602f2c95be8ebe6fc30ccb765facf86cfc5d9dd887aef7ae04e9c5c5855c5fd3a50434");
    ByteArray *d = ba_alloc_from_le_hex_string(
            "6bccbaa912210494fd1a44cec5136f046c0c0a045bac895a3cbd2bccec5e647d0d7fb429f52cb3dcf9941dfb9dfd93133b051fa574589b2ed903933fe2c3ad22");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_init_encrypt_pkcs1_v1_5(ctx, prng, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_pkcs1_v1_5(ctx, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted);
    rsa_free(ctx);
}

static void test_rsa_oaep_with_not_null_label(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *n = ba_alloc_from_le_hex_string(
            "5f7e4cc092b7d3a830d2000290d8bf175bdddeee82b03ea8d392fcf291602f2c95be8ebe6fc30ccb765facf86cfc5d9dd887aef7ae04e9c5c5855c5fd3a50434");
    ByteArray *d = ba_alloc_from_le_hex_string(
            "6bccbaa912210494fd1a44cec5136f046c0c0a045bac895a3cbd2bccec5e647d0d7fb429f52cb3dcf9941dfb9dfd93133b051fa574589b2ed903933fe2c3ad22");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    ByteArray *label = ba_alloc_from_le_hex_string("aa");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA1, label, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA1, label, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted, label);
    rsa_free(ctx);
}

static void test_rsa_init_encrypt_oaep_SHA256(void)
{
    ByteArray *n = ba_alloc_from_le_hex_string(
            "5f7e4cc092b7d3a830d2000290d8bf175bdddeee82b03ea8d392fcf291602f2c95be8ebe6fc30ccb765facf86cfc5d9dd887aef7ae04e9c5c5855c5fd3a50434");
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA256, NULL, n, e);
    const ErrorCtx *err_ctx = stacktrace_get_last();
    ASSERT_TRUE(err_ctx->error_code == RET_INVALID_PARAM);

cleanup:

    prng_free(prng);
    BA_FREE(e, n);
    rsa_free(ctx);
}

static void test_rsa_oaep_SHA256(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *d = ba_alloc_from_be_hex_string(
            "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425");
    ByteArray *n = ba_alloc_from_be_hex_string(
            "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
    ByteArray *e = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    prng = test_utils_get_prng();
    ASSERT_RET_OK(rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA256, NULL, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA256, NULL, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted);
    rsa_free(ctx);
}

static void test_rsa_oaep_SHA384(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *d = ba_alloc_from_be_hex_string(
            "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425");
    ByteArray *n = ba_alloc_from_be_hex_string(
            "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991");
    ByteArray *e = ba_alloc_from_be_hex_string(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    ASSERT_NOT_NULL(ctx = rsa_alloc());

    prng = test_utils_get_prng();
    ASSERT_RET_OK(rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA384, NULL, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA384, NULL, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted);
    rsa_free(ctx);
}

static void test_rsa_oaep_SHA512(void)
{
    ByteArray *plain_data = ba_alloc_from_str("abcdefgh");
    ByteArray *cipher_data = NULL;
    ByteArray *decrypted = NULL;
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    ByteArray *n =
            ba_alloc_from_le_hex_string("576ff776be856ff7e053175b1beea7919d01f948058115c3d89fbf7d6994fb528cdd67991f4d05c66381238623ddfaf88fb2adc91acf5e2242fbc2faff9daaacea3a0bdf6931cce8ec91a521da439c114fcc01d1de313e9a192d84afff465c68bb0c1d0e34bdb9a68e8b1125b33d8e4e1222f3991ebcc6dbfb6c5caca4af60907b6500715d9f009257abe1cd6a4976aa3061b66c05611c06033437ab6e8c13d9da323b8bc361a333d392b96ba19ba3412e43017ca422d3b5c1756d27f8bd8ee94d923fb2bf4b0f32ec140985b25c64333e9f349e628cf5a7541de801978e6d03d94a8e089b4d77ff17fea48f6ab783b55a07b55e9f6d3bc0848c914f12697d39");
    ByteArray *d =
            ba_alloc_from_le_hex_string("6bcff5e1818548640cd80cbf9d93087921bfc2f25731833e658a2ba96738fbd927905ae4ddcda05ab59b565de19557a9da6eced57f3a884cfd00ffe94e983fe9d631f1562d3d65587af183883fed24f8ada41a3a09bee1930be7dff75aaa7868974ec5e120f924af26f8a8ed1096ad65dd2a8df426d8f5a9a0789bb554e755eda64300f6e814abb68fc7eb334786f9c675ebce9d0396bdaeac227ac749080de691cc7c072d41c27737b77bf2c067c22b74d700a86d6c3779d6a3f3c4fad309f1330cd5762addb4769db8b058cc3d9877296a7869ecb2a31ae3684501ba094902e631b40512894faabafe6d0a477a02793c5a233f6a9e27805808618a619b5326");

    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;

    ASSERT_NOT_NULL(ctx = rsa_alloc());

    prng = test_utils_get_prng();
    ASSERT_RET_OK(rsa_init_encrypt_oaep(ctx, prng, RSA_HASH_SHA512, NULL, n, e));
    ASSERT_RET_OK(rsa_encrypt(ctx, plain_data, &cipher_data));

    rsa_free(ctx);
    ASSERT_NOT_NULL(ctx = rsa_alloc());

    ASSERT_RET_OK(rsa_init_decrypt_oaep(ctx, RSA_HASH_SHA512, NULL, n, d));
    ASSERT_RET_OK(rsa_decrypt(ctx, cipher_data, &decrypted));

    ASSERT_EQUALS_BA(plain_data, decrypted);

cleanup:

    prng_free(prng);
    BA_FREE(e, d, n, plain_data, cipher_data, decrypted);
    rsa_free(ctx);
}

static void rsa_extended_validate(void)
{
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    RsaCtx *ctx = NULL;
    ByteArray *n =
            ba_alloc_from_le_hex_string("412dfacda658456a80c23593103fedc58b0822b258f953b9fbe9cfa6d5c3e9644c7612f25787a549a70c2465b16613e84cd29b33e05e8e747b134856e0845c90");
    ByteArray *d =
            ba_alloc_from_le_hex_string("0345331dcb186bd7b4e56eb366476a94a04f2e92fdbc738fcf2b6f63c3fbf34287f9b6f68fafc3dbc45d6d4376446245338c12cdeae95ef8fc0c30e4eaad3d60");
    ByteArray *p = ba_alloc_from_le_hex_string("6fc76c2ea74f36394bc4302dc29876497f34172fc0bdc4c5cb75f7cbae11dcc0");
    ByteArray *q = ba_alloc_from_le_hex_string("4f7ec0f3ce63eeeda5a5de58343bd79d9b5cc5271ca0619c78b2b1c581b89fbf");
    ByteArray *dmp1 = ba_alloc_from_le_hex_string("9f2ff31e1a35242632d8757381104f86ff22ba74d5d32dd9874efa8774b69280");
    ByteArray *dmq1 = ba_alloc_from_le_hex_string("dffe2a4ddf97494919193f3b78273a691293831a6815416850cccb8356d0bf7f");
    ByteArray *iqmp = ba_alloc_from_le_hex_string("331dbcdf114ae665e7beb5003b17a84e9bf7abd3e3544635016e5a8b0f2b194b");

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_validate_key(ctx, n, e, d, p, q, dmp1, dmq1, iqmp) ? RET_OK : RET_VERIFY_FAILED);

cleanup:

    BA_FREE(e, n, d, p, q, dmp1, dmq1, iqmp);
    rsa_free(ctx);
}

static void rsa_extended_gen_validate(void)
{
    ByteArray *e = ba_alloc_from_le_hex_string("03");
    RsaCtx *ctx = NULL;
    ByteArray *n = NULL;

    ByteArray *d = NULL;
    ByteArray *p = NULL;
    ByteArray *q = NULL;
    ByteArray *dmp1 = NULL;
    ByteArray *dmq1 = NULL;
    ByteArray *iqmp = NULL;
    PrngCtx *prng = NULL;

    ASSERT_NOT_NULL(prng = test_utils_get_prng());

    ASSERT_NOT_NULL(ctx = rsa_alloc());
    ASSERT_RET_OK(rsa_generate_privkey_ext(ctx, prng, 257, e, &n, &d, &p, &q, &dmp1, &dmq1, &iqmp));
    ASSERT_RET_OK(rsa_validate_key(ctx, n, e, d, p, q, dmp1, dmq1, iqmp) ? RET_OK : RET_VERIFY_FAILED);

cleanup:

    BA_FREE(e, n, d, p, q, dmp1, dmq1, iqmp);
    rsa_free(ctx);
    prng_free(prng);
}

#ifdef FULL_UTEST
static void rsa_possible_bits_test(void)
{
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *n = NULL;
    ByteArray *priv_key = NULL;
    uint8_t e_u8 = 3;
    ByteArray *e = ba_alloc_from_uint8(&e_u8, 1);

    seed = ba_alloc_by_len(40);
    ba_set(seed, 0xba);

    prng = prng_alloc(PRNG_MODE_DEFAULT, seed);

    ctx = rsa_alloc();

    for(int i = 0; i < 64; i++) {
        size_t bit_num = 256 + i;
        ASSERT_RET_OK(rsa_generate_privkey(ctx, prng, bit_num, e, &n, &priv_key));

        ba_free(n);
        ba_free(priv_key);
        n = NULL;
        priv_key = NULL;
    }

cleanup:

    ba_free(seed);
    prng_free(prng);
    rsa_free(ctx);

}
#endif

void utest_rsa(void)
{
    PR("%s\n", __FILE__);

    test_rsa_sign();
    test_rsa_sign2();
    test_rsa_sign3();
    test_rsa_sign4();
    test_rsa_sign5_hash_len_is_not_valid();
    test_rsa_oaep_SHA1();
    test_rsa_init_encrypt_oaep_SHA256();
    test_rsa_oaep_SHA256();
    test_rsa_oaep_SHA384();
    test_rsa_oaep_SHA512();
    test_rsa_oaep_with_not_null_label();
    test_rsa_pkcs1_v1_5();
    rsa_extended_validate();
    rsa_extended_gen_validate();

#ifdef FULL_UTEST
    rsa_possible_bits_test();
#endif

}
