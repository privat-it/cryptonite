/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "sha2.h"


static void sha224_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("d243bf9e0874b3867452f9602c53a2758f17653069491c8bdcaceb33");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_224));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_RET_OK(sha2_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
}

static void sha224_hash_2(void)
{
    ByteArray *data =
            ba_alloc_from_str("CryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("a8702fab5b57072c3d52f70d8655674d2f33081392387957182f249d");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_224));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_RET_OK(sha2_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
}

static void sha224_hash_2_copy_with_alloc(void)
{
    ByteArray *data =
            ba_alloc_from_str("CryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptoniteCryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("a8702fab5b57072c3d52f70d8655674d2f33081392387957182f249d");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;
    Sha2Ctx *ctx_copy = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_224));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_NOT_NULL(ctx_copy = sha2_copy_with_alloc(ctx));
    sha2_free(ctx);
    ctx = NULL;
    ASSERT_RET_OK(sha2_final(ctx_copy, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
    sha2_free(ctx_copy);
}

static void sha256_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_256));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_RET_OK(sha2_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
}

static void sha384_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "876c0f24643e65a6b383e86888e0204ad1a250d2188cd3751f021244f0ed1d045961616b1e394ee1e4b623c6b4016c39");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_384));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_RET_OK(sha2_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
}

static void sha512_hash(void)
{
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "a7eaa036beb43131b0818c2c324e52310763c95f91dc91234a395b0f1a0ebdd8abe491e426ada2c4700231258347631ac94fa01e43150246cc5d824ac88e420b");
    ByteArray *hash = NULL;
    Sha2Ctx *ctx = NULL;

    ASSERT_NOT_NULL(ctx = sha2_alloc(SHA2_VARIANT_512));
    ASSERT_RET_OK(sha2_update(ctx, data));
    ASSERT_RET_OK(sha2_final(ctx, &hash));

    ASSERT_EQUALS_BA(exp, hash);

cleanup:

    ba_free(exp);
    ba_free(data);
    ba_free(hash);
    sha2_free(ctx);
}

void utest_sha2(void)
{
    PR("%s\n", __FILE__);

    sha224_hash();
    sha224_hash_2();
    sha256_hash();
    sha384_hash();
    sha512_hash();

    sha224_hash_2_copy_with_alloc();
}
