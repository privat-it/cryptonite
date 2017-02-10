/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "sha1.h"

static void test_sha1_1(void)
{
    ByteArray *data = ba_alloc_from_le_hex_string("");
    ByteArray *expected = ba_alloc_from_le_hex_string("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    ByteArray *actual = NULL;
    Sha1Ctx *ctx = sha1_alloc();

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(sha1_update(ctx, data));
    ASSERT_RET_OK(sha1_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    sha1_free(ctx);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void test_sha1_1_copy_with_alloc(void)
{
    ByteArray *data = ba_alloc_from_le_hex_string("");
    ByteArray *expected = ba_alloc_from_le_hex_string("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    ByteArray *actual = NULL;
    Sha1Ctx *ctx = sha1_alloc();
    Sha1Ctx *ctx_copy = NULL;

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(sha1_update(ctx, data));
    ASSERT_NOT_NULL(ctx_copy = sha1_copy_with_alloc(ctx));
    sha1_free(ctx);
    ctx = NULL;
    ASSERT_RET_OK(sha1_final(ctx_copy, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    sha1_free(ctx);
    sha1_free(ctx_copy);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void test_sha1_2(void)
{
    ByteArray *data = ba_alloc_from_le_hex_string(
            "3b46736d559bd4e0c2c1b2553a33ad3c6cf23cac998d3d0c0e8fa4b19bca06f2f386db2dcff9dca4f40ad8f561ffc308b46c5f31a7735b5fa7e0f9e6cb512e63d7eea05538d66a75cd0d4234b5ccf6c1715ccaaf9cdc0a2228135f716ee9bdee7fc13ec27a03a6d11c5c5b3685f51900b1337153bc6c4e8f52920c33fa37f4e7");
    ByteArray *expected = ba_alloc_from_le_hex_string("58429e8f371f9e1d69a5bf96a554d627cfd5485c");
    ByteArray *actual = NULL;
    Sha1Ctx *ctx = sha1_alloc();

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(sha1_update(ctx, data));
    ASSERT_RET_OK(sha1_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    sha1_free(ctx);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

static void test_sha1_3(void)
{
    ByteArray *data =
            ba_alloc_from_le_hex_string("7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da0226fff19d91bc0c25c5be8d3d04d6c7d72c9127ddb96d6f082dd8c6982ddc8419de1fb2e816fde174bc314274a7c0b21059423f37f95128db90a87f379340d914aff32d0c434e9e60df02ef2a055e8484d7f130981ba1ef8c8f29288906bf53a30b2ee2529d3aad6abcc7d5b5b42cd9b53732ce96a6cc4d8b67bf85050e848e157e0755838b2e6902c3e4b8b02a980c11e56b4b8c212cad58c8fff724014ce31c872118f793a68bc982ddeaa1df4ca63b612f4a10f16f9985115f117e9574ecf8a5107f275d3f701f88380df348a7329248d34cadbdf19c90df51466d11a9266a563a2abb3e65a0753277652d0d343ba6fb1bc5badd5f210c917b18882c3609c229229dfbbd95a77b1010b2c783702bf9f64d37d0e604b138c630fa484bc811908c5e3b91616bff91af98695b51e77dfbd90c25785e8ee7d5ec178e35d6bbd865fe4195e4b03513497f72eb40ef06bc3d01cd2139ad5a1f44719326d973adb8b30d614f9e20ad7d12fe34db20b15a613e0f048d6d58f2d2050538669b990a5cf828519b064921b77eba529b634f6f076f6f46fcbbf7e5aab8057bcff4cd4e1fb5dd873ab5802e3cfd1250ae912f9119418108e17df0bef3ae00d1c59d77058b6c9b7681346c4f881ec4c3a732c87d016512cece5bd9cb678765dee9ce2cbd2a9cf0a4210b63f22344100007b0a09f6a4a630d25be29b750a4c3079f3f64d177c76b947c931db2890da2aa32935e54be5210488a1d56ef59b6a6c06849a5eeed6c7adc0673e00d43fbeb36ca634859782c99056e01e7ffed1d6fbdd775666205fc8ccf4116616ece6f581a31a8f4fa222a6bd8440463458549ac346f5b2cd76c083ff2df030853930887e90adcfad346ec17159e8d4f7cacdbeae892637fbb5a1002fb12c24b683c27e907a857b06140e21951e01502f1de448a3ed316c59a8a94642caecca0f9247dfa1abcd1bc10ba9ce121cb2434319404289bb3ed94d16815d22bd58abf92d65b39869ab3848e1e7d1ce9824349d868ab34a3c770740c6d14db5d59a4edd1ec4035dfd4759025e7231b3dd7eaba42c69a4cdb5027d9b81401ee559d73b212b0dd6d8afca065749eff6a832e930c0d3861cfa7107c3c40f76d998903afb2f1de835f1c65cc7af6c092994de8d4c59428823b9b7af6225381c86b8c3e8156dbbfc27908c2425728d66d1612a9186d74218c1f2ce21e124c4da2b2c3b0c1145cff2b49d474ba70875aef6f65e1e67a39bdeff8dff86c82b7a57d2dc3dcc781e1f71e40040f8d6daec8aa03bc25b76231581e4729206a0a1233c82b01450d15f7522c0a1bf54384ebaa2d8189d713bc077aa798acfc8f0ee8730449007c1a47297ad4f680b8757cda69da57539873ee28b00c5bbfdf540796edc1f645d477abe4db99a3e6eb8bbc07923103adcc608f2172cd0ee66b419aca0e71b145f09d9ab61eea7092e10ea8dfbde204fcf562056e4d5a20c502e01eee4fa408855304ca199f680b394b66e9ef473dd9c5a5e0e78baa444fb048b82a804bd97a987e35808bf762d22e8d2cf592c8d4f0ac4065bbf6141bda5caf22440c6d7275d3c4b87489919b440728e93286bd27f7f57788e92a05315f0e98b6e1ff3f1f88dbd9060c9f0841ff37910447278ea74e459d92f5b408254c6ab7fe8ad53b2132253d96bf48b6276254780699e1c7e36221354c6810a78830e56f61a52adc37f02444e312f3459bfbd22078b161f36ce1fcd0edc6cc3daaab033178d77cacb4417d81939e3b11104a353cd314149b943c5cf32f8833653cf938a0bc88273736b47595f0b79cb344cbf22f9e38761b09dfb60e6a3302a89fca1a3fa53dd6e63fb7c0d4b30574a67a0f9d6b32a5031c2e5a8c95264db662438c1c50bb7ee8342fc9d3e022fe7f6540739b9258c047f9822b653a0c3eab3cd8cdb3a667b1f7cb9779232af909097a389671174930b14d95c0c43f548c6d92cfed8483427d7206f72433178dcb9f4fc2e6b27cbc7ceb82e9b92e47c7cd7a0e8999e389d447d360df89885859accd605ff2d4350afb3323fe8307d5ae685d0a9621652c8597b873a0e7975ff523005690395ad2bd3234cb34ace55ba0f3930196328dddeee38db9fbece480e8d4d49ce428cac85bb87cc33ca54b5c27d5989dea3bd23068b1cf9e30f7f47d9d18b6addc5f88986f0457b666faae59aba4fa3a02abb6a69b98fabaf0a74ba89a9522f3d93c38d55f9c721f541b92d6b4e814608010cfb2efff9b7abb595e9459a0a6196b4d3fd1b5e7386874867d55dbf593abd2f961e7ee6c2e67e1acb1b362e1bc892311224ffa8b371c58d9d2497973d4668bc431a81f55200d141fc9984eced2cd71166492a5eeeac56174463425d9734b1b1f9395eb412cd4b3011ac565ce8550d5cb9b37810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b58c36997f0d53a37919815cc123fd5da7810aed4d42c0606d0c1f76943d0c63f38d261cdaa6244b");
    ByteArray *expected = ba_alloc_from_le_hex_string("985db87dc59b57d220d6bf0750c7b610d20db52d");
    ByteArray *actual = NULL;
    Sha1Ctx *ctx = sha1_alloc();

    ASSERT_NOT_NULL(ctx);
    ASSERT_RET_OK(sha1_update(ctx, data));
    ASSERT_RET_OK(sha1_final(ctx, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    sha1_free(ctx);
    ba_free(data);
    ba_free(expected);
    ba_free(actual);
}

void utest_sha1(void)
{
    PR("%s\n", __FILE__);

    test_sha1_1();
    test_sha1_2();
    test_sha1_3();
    test_sha1_1_copy_with_alloc();
}
