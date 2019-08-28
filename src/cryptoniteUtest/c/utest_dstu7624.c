/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "paddings.h"

#include "dstu7624.h"

static const uint8_t s_blocks[] = {
    0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09,
    0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39,
    0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6,
    0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1,
    0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27,
    0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41,
    0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e,
    0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55,
    0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff,
    0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1,
    0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76,
    0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26,
    0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82,
    0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8,
    0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d,
    0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80,

    0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8,
    0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d,
    0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d,
    0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc,
    0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee,
    0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca,
    0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20,
    0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f,
    0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51,
    0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98,
    0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9,
    0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05,
    0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82,
    0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad,
    0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59,
    0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7,

    0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59,
    0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1,
    0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72,
    0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90,
    0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35,
    0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48,
    0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38,
    0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33,
    0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29,
    0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83,
    0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2,
    0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43,
    0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82,
    0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91,
    0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44,
    0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67,

    0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f,
    0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd,
    0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66,
    0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf,
    0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99,
    0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71,
    0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60,
    0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b,
    0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09,
    0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2,
    0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7,
    0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a,
    0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39,
    0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef,
    0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36,
    0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61
};

static void dstu7624_key_gen(void)
{
    ByteArray *data = ba_alloc_from_le_hex_string("00000000000000000000000000000000");
    Dstu7624Ctx *ctx = NULL;
    ByteArray *key = NULL;
    ByteArray *cipher = NULL;
    ByteArray *enc = NULL;
    PrngCtx *prng = NULL;

    prng = test_utils_get_prng();

    ASSERT_RET_OK(dstu7624_generate_key(prng, 16, &key));
    ASSERT_NOT_NULL(key);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &enc));

    ASSERT_EQUALS_BA(data, enc);

cleanup:

    prng_free(prng);
    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(enc);
    ba_free(cipher);
}

static void dstu7624_ecb_16_16_usr_sbox(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("81BF1C7D779BAC20E1C9EA39B4D2AD06");
    ByteArray *sbox = ba_alloc_from_uint8(s_blocks, sizeof(s_blocks));

    ASSERT_NOT_NULL(ctx = dstu7624_alloc_user_sbox(sbox));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    BA_FREE(sbox, key, data, exp, cipher);
}

static void dstu7624_ecb_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("81BF1C7D779BAC20E1C9EA39B4D2AD06");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_ecb_16_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("58EC3E091000158A1148F7166F334F14");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_ecb_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("F66E3D570EC92135AEDAE323DCBD2A8CA03963EC206A0D5A88385C24617FD92C");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 32));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_ecb_32_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("606990E9E6B7B67A4BD6D893D72268B78E02C83C3CD7E102FD2E74A8FDFE5DD9");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 32));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_ecb_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "4A26E31B811C356AA61DD6CA0596231A67BA8354AA47F3A13E1DEEC320EB56B895D0F417175BAB662FD6F134BB15C86CCB906A26856EFEB7C5BC6472940DD9D9");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ecb(ctx, key, 64));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;

    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_ctr_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *data1 = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F30313233343536");
    ByteArray *data2 = ba_alloc_from_le_hex_string("3738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *enc_data1 = NULL;
    ByteArray *enc_data2 = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "A90A6B9780ABDFDFF64D14F5439E88F266DC50EDD341528DD5E698E2F000CE21F872DAF9FE1811844A");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

    ba_free(cipher);
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data1, &cipher1));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data2, &cipher2));

    ASSERT_NOT_NULL(cipher = ba_join(cipher1, cipher2));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher1, &enc_data1));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher2, &enc_data2));

    ASSERT_NOT_NULL(cipher = ba_join(enc_data1, enc_data2));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    BA_FREE(key, data, data1, data2, iv, exp, cipher, cipher1, cipher2, enc_data1, enc_data2);
    dstu7624_free(ctx);
}

static void dstu7624_cfb_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
//    ByteArray *data1 = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F30313233343536");
//    ByteArray *data2 = ba_alloc_from_le_hex_string("3738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *cipher_stream = NULL;
    ByteArray *encoded = NULL;
    ByteArray *cipher1 = NULL;
    ByteArray *cipher2 = NULL;
    ByteArray *enc_data1 = NULL;
    ByteArray *enc_data2 = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &encoded));

    ASSERT_EQUALS_BA(data, encoded);
    //Стримовый режим пока что недоступный.
//    dstu7624_free(ctx);
//
//    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
//    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
//    ASSERT_RET_OK(dstu7624_encrypt(ctx, data1, &cipher1));
//    ASSERT_RET_OK(dstu7624_encrypt(ctx, data2, &cipher2));
//
//    ASSERT_NOT_NULL(cipher_stream = ba_join(cipher1, cipher2));
//
//    ASSERT_EQUALS_BA(cipher_stream, cipher);
//    ba_free(encoded);
//    cipher = NULL;
//    dstu7624_free(ctx);
//
//    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
//    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
//    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher1, &enc_data1));
//    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher2, &enc_data2));
//
//    ASSERT_NOT_NULL(encoded = ba_join(enc_data1, enc_data2));
//
//    ASSERT_EQUALS_BA(data, encoded);

cleanup:

    BA_FREE(key, data, iv, cipher, cipher1, cipher2, enc_data1, enc_data2, cipher_stream, encoded);
    dstu7624_free(ctx);
}

static void dstu7624_ctr_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "8a355857d43e1e12ddc9ab7c07f9c350a4a946eddce74246bd9756c14db38e82d82da491af959c79bc225bd9acaf1428f15cb321e1eae2a3a6aa12c417949677d5f930367f40241b9c7c4e8d771a56b7eba1");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(iv);
    ba_free(cipher);
}

static void dstu7624_ctr_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string(
            "101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "7009ea4ff158689a5f607a807ba2ad3f9beccef21a8712d37d2712a0ca51e9e067d2e0f4c91658f48d42ae13e9e221223ccd065125a2ed0e5451c5083160dfd20e1820190913f1290c40f3e558378de6aabfeec64f505fdcd2888533b29c4fc4aee8201f3e60af781c6fc31d6445a797b776b55743c8ce5140990ac714b890ac7e2b7854d1576b3202149e615d7e01458bc8d8317c10c8268f99cf63a12f17035e5c5b29");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ctr(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_EQUALS_BA(data, cipher);

cleanup:


    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(iv);
    ba_free(exp);
    ba_free(cipher);
}

static void dstu7624_cbc_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *result = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "a73625d7be994e85469a9faabcedaab6dbc5f65dd77bb35e06bd7d1d8eafc86261df4b314b80436f5434e0efa80be0ed");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));

    ASSERT_RET_OK(make_iso_7816_4_padding(data, (uint8_t)ba_get_len(iv), &result))
    ASSERT_RET_OK(dstu7624_encrypt(ctx, result, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    ba_free(result);
    cipher = NULL;
    result = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));

    ASSERT_RET_OK(make_iso_7816_4_unpadding(cipher, &result))
    ASSERT_EQUALS_BA(data, result);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(iv);
    ba_free(data);
    ba_free(exp);
    ba_free(cipher);
    ba_free(result);
}

static void dstu7624_cbc_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "0ae0780c2eaf54065d181e5339fc94a50dbeca17069769e5c23cdc7bdad6adfcd93e59097469be420c164d90aae17ec0dc8e9b11412e5b3c812fbb0204313abe0d5b0adfb5187be6868f6bfddc096ffa1a5294cc90b49605b7f3cc3532d4604c");
    ByteArray *data_padd = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(make_iso_7816_4_padding(data, (uint8_t)ba_get_len(iv), &data_padd));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data_padd, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    ba_free(data_padd);
    data_padd = NULL;
    cipher = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));
    ASSERT_RET_OK(make_iso_7816_4_unpadding(cipher, &data_padd));

    ASSERT_EQUALS_BA(data, data_padd);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(iv);
    ba_free(data);
    ba_free(exp);
    ba_free(data_padd);
    ba_free(cipher);
}

static void dstu7624_cbc_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string(
            "101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "4f3a325c87bba4a82333123604fe1e506a99bfdec970a3d5deeef5c51181674309c7b8beddbdfeeddc414913d2c4cfba17ea80767b588f70a4cbb2b3acef3ed2bdab23f45a7bc8dc89167eede2d7480950ab19eae1368113c18df1b01fdeec1f82973463c1e8a09c09151388e5fa5ca21b23daa2403c971d421d5473d4f5ab1c6358861372f5987b76c88a3bff9cd71c0d0006d58fca8afa095922a49029d1ab6ea28ba136c6368fbae9847587873f8d1318296f1c49d153e6680b21f36ec881");
    ByteArray *data_padd = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(make_iso_7816_4_padding(data, (uint8_t)ba_get_len(iv), &data_padd));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data_padd, &cipher));

    ASSERT_EQUALS_BA(exp, cipher);
    ba_free(cipher);
    cipher = NULL;
    ba_free(data_padd);
    data_padd = NULL;
    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cbc(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, exp, &cipher));
    ASSERT_RET_OK(make_iso_7816_4_unpadding(cipher, &data_padd));

    ASSERT_EQUALS_BA(data, data_padd);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(iv);
    ba_free(data_padd);
    ba_free(cipher);
}

static void dstu7624_cfb_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(iv);
    ba_free(data);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_cfb_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string(
            "101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cfb(ctx, key, iv, 16));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(iv);
    ba_free(data);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_xts_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(iv);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_xts_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(iv);
    ba_free(cipher);
}

static void dstu7624_xts_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *iv = ba_alloc_from_le_hex_string(
            "101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F101112131415161718191A1B1C1D1E1F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_xts(ctx, key, iv));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(iv);
    ba_free(cipher);
}

static void dstu7624_kw_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 16));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_kw_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 32));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 32));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_kw_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *cipher = NULL;
    ByteArray *plain = NULL;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 64));
    ASSERT_RET_OK(dstu7624_encrypt(ctx, data, &cipher));

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_kw(ctx, key, 64));
    ASSERT_RET_OK(dstu7624_decrypt(ctx, cipher, &plain));

    ASSERT_EQUALS_BA(data, plain);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(plain);
    ba_free(cipher);
}

static void dstu7624_cmac_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("123B4EAB8E63ECF3E645A99C1115E241");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cmac(ctx, key, 16, 16));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_cmac_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("5df20d04735bab6d5351082da6ad8d41");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cmac(ctx, key, 32, 16));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_cmac_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("7d0d5fd504115264ea173266f3267a89");
    ;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_cmac(ctx, key, 64, 16));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_gmac_16_16(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("7ce770b1a6bd5fcb704bf23216e53f1f");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gmac(ctx, key, 16, 16));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_gmac_32_32(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    ByteArray *key = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("FF48B56F2C26CC484B8F5952D7B3E1FE69577701C50BE96517B33921E44634CD");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gmac(ctx, key, 32, 32));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_gmac_64_64(void)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string(
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
    ByteArray *key = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *mac = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(
            "897C32E05E776FD988C5171FE70BB72949172E514E3308A871BA5BD898FB6EBD6E3897D2D55697D90D6428216C08052E3A5E7D4626F4DBBF1546CE21637357A3");

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gmac(ctx, key, 64, 64));
    ASSERT_RET_OK(dstu7624_update_mac(ctx, data));
    ASSERT_RET_OK(dstu7624_final_mac(ctx, &mac));

    ASSERT_EQUALS_BA(exp, mac);

cleanup:

    dstu7624_free(ctx);
    ba_free(key);
    ba_free(data);
    ba_free(exp);
    ba_free(mac);
}

static void dstu7624_gcm_16_16(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string("303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F");
    ByteArray *au_ba = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string("C8310571CD60F9584B45C1B4ECE179AF");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "B91A7B8790BBCFCFE65D04E5538E98E216AC209DA33122FDA596E8928070BE51");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 16;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

static void dstu7624_gcm_32_32(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string(
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
    ByteArray *au_ba = ba_alloc_from_le_hex_string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string("1D61B0A3018F6B849CBA20AF1DDDA245");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE80");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 16;


    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

static void dstu7624_gcm_64_64(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string(
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
    ByteArray *au_ba = ba_alloc_from_le_hex_string(
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string(
            "78A77E5948F5DC05F551486FDBB44898C9AB1BD439D7519841AE31007C09E1B312E5EA5929F952F6A3EEF5CBEAEF262B8EC1884DFCF4BAAF7B5C9291A22489E1");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 64;


    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_gcm(ctx, key_ba, iv_ba, q));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

static void dstu7624_ccm_16_16(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string("303132333435363738393A3B3C3D3E3F");
    ByteArray *au_ba = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string("101112131415161718191A1B1C1D1E1F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string("26A936173A4DC9160D6E3FDA3A974060");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "B91A7B8790BBCFCFE65D04E5538E98E2704454C9DD39ADACE0B19D03F6AAB07E");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 16;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 32));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 32));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

static void dstu7624_ccm_32_32(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string(
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
    ByteArray *au_ba = ba_alloc_from_le_hex_string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string("9AB831B4B0BF0FDBC36E4B4FD58F0F00");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "7EC15C54BB553CB1437BE0EFDD2E810F6058497EBCE4408A08A73FADF3F459D56B0103702D13AB73ACD2EB33A8B5E9CFFF5EB21865A6B499C10C810C4BAEBE809C48AD90A9E12A68380EF1C1B7C83EE1");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 16;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 32));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 32));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

static void dstu7624_ccm_64_64(void)
{
    ByteArray *key_ba = ba_alloc_from_le_hex_string(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
    ByteArray *pl_ba = ba_alloc_from_le_hex_string(
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
    ByteArray *au_ba = ba_alloc_from_le_hex_string(
            "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
    ByteArray *iv_ba = ba_alloc_from_le_hex_string(
            "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");
    ByteArray *exp_h_ba = ba_alloc_from_le_hex_string(
            "D4155EC3D888C8D32FE184AC260FD60F567705E1DF362A6F1F9C287156AA96D91BC4C56F9709E72F3D79CF0A9AC8BDC2BA836BE50E823AB50FB1B39080390923");
    ByteArray *exp_cip_ba = ba_alloc_from_le_hex_string(
            "220642D7277D104788CF97B10210984F506435512F7BF153C5CDABFECC10AFB4A2E2FC51F616AF80FFDD0607FAD4F542B8EF0667717CE3EAAA8FBC303CE76C99"\
            "BD8F80CE149143C04FC2490272A31B029DDADA82F055FE4ABEF452A7D438B21E59C1D8B3DD4606BAD66A6F36300EF3CE0E5F3BB59F11416E80B7FC5A8E8B057A");
    ByteArray *act_h_ba = NULL;
    ByteArray *act_cip_ba = NULL;
    ByteArray *exp_dec_ba = NULL;
    Dstu7624Ctx *ctx = NULL;
    size_t q = 64;

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 64));
    ASSERT_RET_OK(dstu7624_encrypt_mac(ctx, au_ba, pl_ba, &act_h_ba, &act_cip_ba));

    ASSERT_EQUALS_BA(exp_h_ba, act_h_ba);
    ASSERT_EQUALS_BA(exp_cip_ba, act_cip_ba);

    dstu7624_free(ctx);

    ASSERT_NOT_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    ASSERT_RET_OK(dstu7624_init_ccm(ctx, key_ba, iv_ba, q, 64));
    ASSERT_RET_OK(dstu7624_decrypt_mac(ctx, au_ba, act_cip_ba, act_h_ba, &exp_dec_ba));

    ASSERT_EQUALS_BA(pl_ba, exp_dec_ba);

cleanup:

    BA_FREE(pl_ba, act_h_ba, key_ba, iv_ba, exp_h_ba, au_ba, act_cip_ba, exp_cip_ba, exp_dec_ba);
    dstu7624_free(ctx);
}

void utest_dstu7624(void)
{
    PR("%s\n", __FILE__);

    dstu7624_key_gen();
    dstu7624_ecb_16_16_usr_sbox();
    dstu7624_ecb_16_16();
    dstu7624_ecb_16_32();
    dstu7624_ecb_32_32();
    dstu7624_ecb_32_64();
    dstu7624_ecb_64_64();
    dstu7624_ctr_16_16();
    dstu7624_ctr_32_32();
    dstu7624_ctr_64_64();
    dstu7624_cbc_16_16();
    dstu7624_cbc_32_32();
    dstu7624_cbc_64_64();
    dstu7624_cfb_16_16();
    dstu7624_cfb_32_32();
    dstu7624_cfb_64_64();
    dstu7624_xts_16_16();
    dstu7624_xts_32_32();
    dstu7624_xts_64_64();
    dstu7624_kw_16_16();
    dstu7624_kw_32_32();
    dstu7624_kw_64_64();
    dstu7624_cmac_16_16();
    dstu7624_cmac_32_32();
    dstu7624_cmac_64_64();
    dstu7624_gmac_16_16();
    dstu7624_gmac_32_32();
    dstu7624_gmac_64_64();
    dstu7624_gcm_16_16();
    dstu7624_gcm_32_32();
    dstu7624_gcm_64_64();
    dstu7624_ccm_16_16();
    dstu7624_ccm_32_32();
    dstu7624_ccm_64_64();
}
