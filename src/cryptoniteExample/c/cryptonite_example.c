/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdio.h>

#include "aes.h"
#include "byte_array.h"
#include "cryptonite_errors.h"
#include "des.h"
#include "dsa.h"
#include "dstu4145.h"
#include "dstu7564.h"
#include "dstu7624.h"
#include "ecdsa.h"
#include "gost28147.h"
#include "gost34_311.h"
#include "hmac.h"
#include "md5.h"
#include "opt_level.h"
#include "prng.h"
#include "rs.h"
#include "rsa.h"
#include "sha1.h"
#include "sha2.h"
#include "stacktrace.h"

static size_t error_count = 0;

#define PR(...)                     printf(__VA_ARGS__); fflush(stdout);
#define CHECK_NULL(param)           if(!(param)){PR("MEMORY ALLOC ERROR\n");error_count++;goto cleanup;}
#define CHECK_RET(param)            if((param) != RET_OK){PR("ERROR CODE WAS RETURNED. LINE: %d, ERROR_CODE: %d\n", __LINE__, param);error_count++;goto cleanup;}
#define CHECK_EQUALS_BA(arg1, arg2) if(ba_cmp((arg1), (arg2))){PR("NOT EQUALS\n");error_count++;goto cleanup;};

const uint8_t data[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
                       };

static __inline ByteArray *generate_ba_key(int (*func)(PrngCtx *, size_t, ByteArray **), size_t key_len)
{
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *key = NULL;

    CHECK_NULL(seed = ba_alloc_by_len(40));
    CHECK_RET(ba_set(seed, 0xaf));

    CHECK_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    CHECK_RET(func(prng, key_len, &key));

cleanup:
    ba_free(seed);
    prng_free(prng);

    return key;
}

static void test_aes_ecb_core(size_t key_len)
{
    AesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка AES режима ECB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, key_len));

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_ecb(ctx, key_ba));

    CHECK_RET(aes_encrypt(ctx, data_ba, &encoded));
    CHECK_RET(aes_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    aes_free(ctx);
}

static void test_aes_ctr_core(size_t key_len)
{
    AesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка AES режима CTR c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 16));

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(aes_encrypt(ctx, data_ba, &encoded));

    aes_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(aes_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    aes_free(ctx);
}

static void test_aes_cfb_core(size_t key_len)
{
    AesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка AES режима CFB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 16));

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(aes_encrypt(ctx, data_ba, &encoded));

    aes_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(aes_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    aes_free(ctx);
}

static void test_aes_ofb_core(size_t key_len)
{
    AesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка AES режима OFB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 16));

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(aes_encrypt(ctx, data_ba, &encoded));

    aes_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(aes_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    aes_free(ctx);
}

static void test_aes_cbc_core(size_t key_len)
{
    AesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка AES режима CBC c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 16));

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(aes_encrypt(ctx, data_ba, &encoded));

    aes_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = aes_alloc());
    CHECK_RET(aes_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(aes_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    aes_free(ctx);
}

static void test_tdes_ecb_core(size_t key_len)
{
    DesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка TDES режима ECB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(des_generate_key, key_len));

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_ecb(ctx, key_ba));

    CHECK_RET(des3_encrypt(ctx, data_ba, &encoded));
    CHECK_RET(des3_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    des_free(ctx);
}

static void test_tdes_ctr_core(size_t key_len)
{
    DesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка TDES режима CTR c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(des_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(des3_encrypt(ctx, data_ba, &encoded));

    des_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(des3_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    des_free(ctx);
}

static void test_tdes_ofb_core(size_t key_len)
{
    DesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка TDES режима OFB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(des_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(des3_encrypt(ctx, data_ba, &encoded));

    des_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(des3_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    des_free(ctx);
}

static void test_tdes_cbc_core(size_t key_len)
{
    DesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка TDES режима CBC c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(des_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(des3_encrypt(ctx, data_ba, &encoded));

    des_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(des3_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    des_free(ctx);
}

static void test_tdes_cfb_core(size_t key_len)
{
    DesCtx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка TDES режима CFB c размером ключа %zu.\n", key_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(des_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(des3_encrypt(ctx, data_ba, &encoded));

    des_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = des_alloc());
    CHECK_RET(des_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(des3_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    des_free(ctx);
}

static void test_dstu7624_ecb_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка ДСТУ7624 режима ECB c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ecb(ctx, key_ba, block_len));

    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_ctr_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка ДСТУ7624 режима CTR c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_ofb_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка ДСТУ7624 режима OFB c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ofb(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_cbc_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка ДСТУ7624 режима CBC c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_cbc(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_cfb_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка ДСТУ7624 режима CFB c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_cfb(ctx, key_ba, iv_ba, block_len));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_cfb(ctx, key_ba, iv_ba, block_len));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_kw_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка ДСТУ7624 режима KW c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_kw(ctx, key_ba, block_len));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_kw(ctx, key_ba, block_len));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_xts_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка ДСТУ7624 режима XTS c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_xts(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_encrypt(ctx, data_ba, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_xts(ctx, key_ba, iv_ba));
    CHECK_RET(dstu7624_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_cmac_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка ДСТУ7624 режима CMAC c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_cmac(ctx, key_ba, block_len, block_len));
    CHECK_RET(dstu7624_update_mac(ctx, data_ba));
    CHECK_RET(dstu7624_final_mac(ctx, &encoded));

cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_gmac_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка ДСТУ7624 режима GMAC c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_gmac(ctx, key_ba, block_len, block_len));
    CHECK_RET(dstu7624_update_mac(ctx, data_ba));
    CHECK_RET(dstu7624_final_mac(ctx, &encoded));

cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    dstu7624_free(ctx);
}

static void test_dstu7624_ccm_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *auth_data_ba = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *mac = NULL;

    PR("----Проверка ДСТУ7624 режима CCM c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));
    CHECK_NULL(auth_data_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ccm(ctx, key_ba, iv_ba, block_len, 64));
    CHECK_RET(dstu7624_encrypt_mac(ctx, auth_data_ba, data_ba, &mac, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_ccm(ctx, key_ba, iv_ba, block_len, 64));
    CHECK_RET(dstu7624_decrypt_mac(ctx, auth_data_ba, encoded, mac, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);

cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(auth_data_ba);
    ba_free(iv_ba);
    ba_free(mac);
    dstu7624_free(ctx);
}


static void test_dstu7624_gcm_core(size_t key_len, size_t block_len)
{
    Dstu7624Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *auth_data_ba = NULL;
    ByteArray *iv_ba = NULL;
    ByteArray *mac = NULL;

    PR("----Проверка ДСТУ7624 режима GCM c размером ключа %zu и размером блока %zu.\n",
            key_len, block_len);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(dstu7624_generate_key, key_len));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, block_len));
    CHECK_NULL(auth_data_ba = ba_alloc_from_uint8(data, block_len));

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_gcm(ctx, key_ba, iv_ba, block_len));
    CHECK_RET(dstu7624_encrypt_mac(ctx, auth_data_ba, data_ba, &mac, &encoded));

    dstu7624_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = dstu7624_alloc(DSTU7624_SBOX_1));
    CHECK_RET(dstu7624_init_gcm(ctx, key_ba, iv_ba, block_len));
    CHECK_RET(dstu7624_decrypt_mac(ctx, auth_data_ba, encoded, mac, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);

cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(auth_data_ba);
    ba_free(iv_ba);
    ba_free(mac);
    dstu7624_free(ctx);
}

static void test_gsot28147_ecb_core(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка GOST28147 режима ECB c размером ключа %d.\n", 32);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = generate_ba_key(aes_generate_key, 32));

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_ecb(ctx, key_ba));

    CHECK_RET(gost28147_encrypt(ctx, data_ba, &encoded));
    CHECK_RET(gost28147_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    gost28147_free(ctx);
}

static void test_gost28147_ctr_core(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка GOST28147 режима CTR c размером ключа %d.\n", 32);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = ba_alloc_from_uint8(data, 32));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(gost28147_encrypt(ctx, data_ba, &encoded));

    gost28147_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_ctr(ctx, key_ba, iv_ba));
    CHECK_RET(gost28147_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    gost28147_free(ctx);
}

static void test_gost28147_cfb_core(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;
    ByteArray *iv_ba = NULL;

    PR("----Проверка GOST28147 режима CFB c размером ключа %d.\n", 32);
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = ba_alloc_from_uint8(data, 32));
    CHECK_NULL(iv_ba = ba_alloc_from_uint8(data, 8));

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(gost28147_encrypt(ctx, data_ba, &encoded));

    gost28147_free(ctx);
    ctx = NULL;

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_cfb(ctx, key_ba, iv_ba));
    CHECK_RET(gost28147_decrypt(ctx, encoded, &decoded));

    CHECK_EQUALS_BA(data_ba, decoded);
cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    ba_free(iv_ba);
    gost28147_free(ctx);
}

static void test_dstu7564_hash_core(size_t hash_len)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *actual = NULL;
    Dstu7564Ctx *ctx = dstu7564_alloc(DSTU7564_SBOX_1);

    PR("----Проверка хэша ДСТУ7564 c размером хэша %zu.\n", hash_len);

    CHECK_NULL(ctx);
    CHECK_RET(dstu7564_init(ctx, hash_len));
    CHECK_RET(dstu7564_update(ctx, data_ba));
    CHECK_RET(dstu7564_final(ctx, &actual));

cleanup:

    dstu7564_free(ctx);
    ba_free(data_ba);
    ba_free(actual);
}

static void test_dstu7564_hmac_core(size_t hmac_len)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *key = ba_alloc_from_uint8(data, 20);
    ByteArray *hmac = NULL;
    Dstu7564Ctx *ctx = NULL;

    PR("----Проверка мака ДСТУ7564 c размером ключа %zu.\n", hmac_len);

    CHECK_NULL(ctx = dstu7564_alloc(DSTU7564_SBOX_1));
    CHECK_RET(dstu7564_init_kmac(ctx, key, hmac_len));
    CHECK_RET(dstu7564_update_kmac(ctx, data_ba));
    CHECK_RET(dstu7564_final_kmac(ctx, &hmac));

cleanup:

    ba_free(data_ba);
    ba_free(hmac);
    ba_free(key);
    dstu7564_free(ctx);
}

static void test_gost34311_hash_core(void)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *sync = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *actual = NULL;
    Gost34311Ctx *ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync);

    PR("----Проверка хэша ГОСТ34311.\n");

    CHECK_NULL(ctx);
    CHECK_RET(gost34_311_update(ctx, data_ba));
    CHECK_RET(gost34_311_final(ctx, &actual));

cleanup:

    gost34_311_free(ctx);
    ba_free(data_ba);
    ba_free(actual);
    ba_free(sync);
}

static void test_md5_hash_core(void)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *hash = NULL;
    Md5Ctx *ctx = NULL;

    PR("----Проверка хэша MD5.\n");
    CHECK_NULL(ctx = md5_alloc());
    CHECK_RET(md5_update(ctx, data_ba));
    CHECK_RET(md5_final(ctx, &hash));

cleanup:

    ba_free(data_ba);
    ba_free(hash);
    md5_free(ctx);
}

static void test_sha1_core(void)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *actual = NULL;
    Sha1Ctx *ctx = sha1_alloc();

    PR("----Проверка хэша SHA1.\n");

    CHECK_NULL(ctx);
    CHECK_RET(sha1_update(ctx, data_ba));
    CHECK_RET(sha1_final(ctx, &actual));

cleanup:

    sha1_free(ctx);
    ba_free(data_ba);
    ba_free(actual);
}

static void test_sha2_hash_core(Sha2Variant variant)
{
    ByteArray *data_ba = ba_alloc_from_str("");
    ByteArray *actual = NULL;
    Sha2Ctx *ctx = sha2_alloc(variant);

    switch (variant) {
    case SHA2_VARIANT_224:
        PR("----Проверка хэша SHA224.\n");
        break;
    case SHA2_VARIANT_256:
        PR("----Проверка хэша SHA256.\n");
        break;
    case SHA2_VARIANT_384:
        PR("----Проверка хэша SHA384.\n");
        break;
    case SHA2_VARIANT_512:
        PR("----Проверка хэша SHA512.\n");
        break;
    default:
        break;
    }

    CHECK_NULL(ctx);
    CHECK_RET(sha2_update(ctx, data_ba));
    CHECK_RET(sha2_final(ctx, &actual));

cleanup:

    sha2_free(ctx);
    ba_free(data_ba);
    ba_free(actual);
}

static void test_gost28147_mac_core(void)
{
    Gost28147Ctx *ctx = NULL;
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;
    ByteArray *key_ba = NULL;
    ByteArray *data_ba = NULL;

    PR("----Проверка GOST28147 режима MAC.\n");
    CHECK_NULL(data_ba = ba_alloc_from_uint8(data, 64));
    CHECK_NULL(key_ba = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    CHECK_NULL(ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
    CHECK_RET(gost28147_init_mac(ctx, key_ba));
    CHECK_RET(gost28147_update_mac(ctx, data_ba));
    CHECK_RET(gost28147_final_mac(ctx, &encoded));

cleanup:
    ba_free(encoded);
    ba_free(decoded);
    ba_free(key_ba);
    ba_free(data_ba);
    gost28147_free(ctx);
}

void test_md5_hmac_core(void)
{
    ByteArray *data = ba_alloc_from_str("");
    ByteArray *key = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    PR("----Проверка мака в MD5.\n");
    CHECK_NULL(ctx = hmac_alloc_md5());
    CHECK_RET(hmac_init(ctx, key));
    CHECK_RET(hmac_update(ctx, data));
    CHECK_RET(hmac_final(ctx, &hmac));

cleanup:

    ba_free(data);
    ba_free(key);
    ba_free(hmac);
    hmac_free(ctx);
}

void test_sha1_hmac_core(void)
{
    ByteArray *data = ba_alloc_from_str("");
    ByteArray *key = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    PR("----Проверка мака в SHA1.\n");
    CHECK_NULL(ctx = hmac_alloc_sha1());
    CHECK_RET(hmac_init(ctx, key));
    CHECK_RET(hmac_update(ctx, data));
    CHECK_RET(hmac_final(ctx, &hmac));

cleanup:

    ba_free(data);
    ba_free(key);
    ba_free(hmac);
    hmac_free(ctx);
}

void test_sha2_hmac_core(Sha2Variant variant)
{
    ByteArray *data = ba_alloc_from_str("");
    ByteArray *key = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ByteArray *hmac = NULL;
    HmacCtx *ctx = NULL;

    switch (variant) {
    case SHA2_VARIANT_224:
        PR("----Проверка мака SHA224.\n");
        break;
    case SHA2_VARIANT_256:
        PR("----Проверка мака SHA256.\n");
        break;
    case SHA2_VARIANT_384:
        PR("----Проверка мака SHA384.\n");
        break;
    case SHA2_VARIANT_512:
        PR("----Проверка мака SHA512.\n");
        break;
    default:
        break;
    }
    CHECK_NULL(ctx = hmac_alloc_sha2(variant));
    CHECK_RET(hmac_init(ctx, key));
    CHECK_RET(hmac_update(ctx, data));
    CHECK_RET(hmac_final(ctx, &hmac));

cleanup:

    ba_free(data);
    ba_free(key);
    ba_free(hmac);
    hmac_free(ctx);
}

void test_dsa_sign_core(void)
{
    DsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *priv_key = NULL;
    ByteArray *pub_key = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *hash_ba = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaa");

    PR("----Проверка подписи DSA.\n");

    CHECK_NULL(seed = ba_alloc_by_len(40));
    ba_set(seed, 0xba);

    CHECK_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    CHECK_NULL(ctx = dsa_alloc_ext(1024, 160, prng));
    CHECK_RET(dsa_generate_privkey(ctx, prng, &priv_key));

    CHECK_RET(dsa_get_pubkey(ctx, priv_key, &pub_key));
    CHECK_RET(dsa_init_sign(ctx, priv_key, prng));

    CHECK_RET(dsa_sign(ctx, hash_ba, &r, &s));

    CHECK_RET(dsa_init_verify(ctx, pub_key));
    CHECK_RET(dsa_verify(ctx, hash_ba, r, s));

cleanup:
    ba_free(seed);
    ba_free(priv_key);
    ba_free(pub_key);
    ba_free(r);
    ba_free(s);
    ba_free(hash_ba);
    dsa_free(ctx);
    prng_free(prng);
}

void test_rsa_sign_core(void)
{
    RsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *n = NULL;
    ByteArray *sign = NULL;
    ByteArray *priv_key = NULL;
    ByteArray *hash_ba = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaa");
    uint8_t e_u8 = 3;
    ByteArray *e = ba_alloc_from_uint8(&e_u8, 1);

    PR("----Проверка подписи RSA PKCS v1.5.\n");

    CHECK_NULL(seed = ba_alloc_by_len(40));
    ba_set(seed, 0xba);

    CHECK_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    CHECK_NULL(ctx = rsa_alloc());
    CHECK_RET(rsa_generate_privkey(ctx, prng, 1024, e, &n, &priv_key));
    CHECK_RET(rsa_init_sign_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, priv_key));

    CHECK_RET(rsa_sign_pkcs1_v1_5(ctx, hash_ba, &sign));
    CHECK_RET(rsa_init_verify_pkcs1_v1_5(ctx, RSA_HASH_SHA1, n, e));

    CHECK_RET(rsa_verify_pkcs1_v1_5(ctx, hash_ba, sign));

cleanup:
    ba_free(seed);
    ba_free(priv_key);
    ba_free(e);
    ba_free(n);
    ba_free(sign);
    ba_free(hash_ba);
    rsa_free(ctx);
    prng_free(prng);
}

void test_ecdsa_sign_core(void)
{
    EcdsaCtx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *priv_key = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *hash_ba = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaa");

    PR("----Проверка подписи ECDSA.\n");

    CHECK_NULL(seed = ba_alloc_by_len(40));
    ba_set(seed, 0xba);

    CHECK_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    CHECK_NULL(ctx = ecdsa_alloc(ECDSA_PARAMS_ID_SEC_P384_R1));
    CHECK_RET(ecdsa_generate_privkey(ctx, prng, &priv_key));
    CHECK_RET(ecdsa_get_pubkey(ctx, priv_key, &qx, &qy));
    CHECK_RET(ecdsa_init_sign(ctx, priv_key, prng));

    CHECK_RET(ecdsa_sign(ctx, hash_ba, &r, &s));

    CHECK_RET(ecdsa_init_verify(ctx, qx, qy));

    CHECK_RET(ecdsa_verify(ctx, hash_ba, r, s));

cleanup:
    ba_free(seed);
    ba_free(r);
    ba_free(s);
    ba_free(priv_key);
    ba_free(qx);
    ba_free(qy);
    ba_free(hash_ba);
    ecdsa_free(ctx);
    prng_free(prng);
}

void test_dstu4145_sign_core(void)
{
    Dstu4145Ctx *ctx = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *priv_key = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *hash_ba = ba_alloc_from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    PR("----Проверка подписи DSTU4145.\n");

    CHECK_NULL(seed = ba_alloc_by_len(40));
    ba_set(seed, 0xba);

    CHECK_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

    CHECK_NULL(ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
    CHECK_RET(dstu4145_generate_privkey(ctx, prng, &priv_key));
    CHECK_RET(dstu4145_get_pubkey(ctx, priv_key, &qx, &qy));
    CHECK_RET(dstu4145_init_sign(ctx, priv_key, prng));

    CHECK_RET(dstu4145_sign(ctx, hash_ba, &r, &s));

    CHECK_RET(dstu4145_init_verify(ctx, qx, qy));

    CHECK_RET(dstu4145_verify(ctx, hash_ba, r, s));

cleanup:
    ba_free(seed);
    ba_free(r);
    ba_free(s);
    ba_free(priv_key);
    ba_free(qx);
    ba_free(qy);
    ba_free(hash_ba);
    dstu4145_free(ctx);
    prng_free(prng);
}

static __inline void AES_CORE(void (*aes_func)(size_t key_len))
{
//    aes_func(16);
//    aes_func(24);
    aes_func(32);
}

static __inline void DES_CORE(void (*des_func)(size_t key_len))
{
//    des_func(8);
//    des_func(16);
    des_func(24);
}

static __inline void DSTU7624_CORE(void (*dstu7624_func)(size_t key_len, size_t block_len))
{
//    dstu7624_func(16, 16);
//    dstu7624_func(32, 16);
//    dstu7624_func(32, 32);
//    dstu7624_func(64, 32);
    dstu7624_func(64, 64);
}

static __inline void DSTU7564_HASH_CORE(void)
{
//    int i = 0;
//    for (i = 1; i <= 64; i++) {
    test_dstu7564_hash_core(64);
//    }
}

static __inline void SHA2_HASH_CORE(void)
{
//    test_sha2_hash_core(SHA2_VARIANT_224);
//    test_sha2_hash_core(SHA2_VARIANT_256);
//    test_sha2_hash_core(SHA2_VARIANT_384);
    test_sha2_hash_core(SHA2_VARIANT_512);
}

static __inline void SHA2_HMAC_CORE(void)
{
//    test_sha2_hmac_core(SHA2_VARIANT_224);
//    test_sha2_hmac_core(SHA2_VARIANT_256);
//    test_sha2_hmac_core(SHA2_VARIANT_384);
    test_sha2_hmac_core(SHA2_VARIANT_512);
}

static __inline void DSTU7564_HMAC_CORE(void)
{
//    test_dstu7564_hmac_core(32);
//    test_dstu7564_hmac_core(48);
    test_dstu7564_hmac_core(64);
}

int main(void)
{

    PR("Проверка шифрования/рассшифрования симметричных алгоритмов.\n");

    PR("--AES\n");
    AES_CORE(test_aes_ecb_core);
    AES_CORE(test_aes_ctr_core);
    AES_CORE(test_aes_ofb_core);
    AES_CORE(test_aes_cbc_core);
    AES_CORE(test_aes_cfb_core);

    PR("--DES\n");
    DES_CORE(test_tdes_ecb_core);
    DES_CORE(test_tdes_ctr_core);
    DES_CORE(test_tdes_ofb_core);
    DES_CORE(test_tdes_cbc_core);
    DES_CORE(test_tdes_cfb_core);

    PR("--DSTU7624\n");
    DSTU7624_CORE(test_dstu7624_ecb_core);
    DSTU7624_CORE(test_dstu7624_ctr_core);
    DSTU7624_CORE(test_dstu7624_ofb_core);
    DSTU7624_CORE(test_dstu7624_cbc_core);
    DSTU7624_CORE(test_dstu7624_cfb_core);
    DSTU7624_CORE(test_dstu7624_kw_core);
    DSTU7624_CORE(test_dstu7624_xts_core);
    DSTU7624_CORE(test_dstu7624_ccm_core);
    DSTU7624_CORE(test_dstu7624_gcm_core);

    PR("--GOST28147\n");
    test_gsot28147_ecb_core();
    test_gost28147_ctr_core();
    test_gost28147_cfb_core();

    PR("Проверка хэширования.\n");

    PR("--DSTU7564\n");
    DSTU7564_HASH_CORE();

    PR("--GOST34311\n");
    test_gost34311_hash_core();

    PR("--MD5\n");
    test_md5_hash_core();

    PR("--SHA1\n");
    test_sha1_core();

    PR("--SHA2\n");
    SHA2_HASH_CORE();

    PR("Проверка мака.\n");

    PR("--DSTU7564\n");
    DSTU7564_HMAC_CORE();

    PR("--DSTU7624\n");
    DSTU7624_CORE(test_dstu7624_cmac_core);
    DSTU7624_CORE(test_dstu7624_gmac_core);

    PR("--GOST28147\n");
    test_gost28147_mac_core();

    PR("--MD5\n");
    test_md5_hmac_core();

    PR("--SHA1\n");
    test_sha1_hmac_core();

    PR("--SHA2\n");
    SHA2_HMAC_CORE();

    PR("Проверка подписи ассиметричными алгоритмами.\n");

    PR("--DSA\n");
    test_dsa_sign_core();

    PR("--RSA\n");
    test_rsa_sign_core();

    PR("--ECDSA\n");
    test_ecdsa_sign_core();

    PR("--DSTU4145\n");
    test_dstu4145_sign_core();

    PR("\n Количество ошибок: %zu\n\n", error_count);

    return 0;
}
