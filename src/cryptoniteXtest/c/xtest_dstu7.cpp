#include "xtest.h"
#include "dstu7564.h"
#include "dstu7624.h"

#include "kupyna.h"
#include "kalyna.h"
#include "block_cipher.h"
#include "cbc.h"
#include "stream_cipher.h"

using namespace cppcrypto;;

#define XTEST_LIB_NUM 2

static void xtest_dstu7564_256(XtestSt *ctx, TableBuilder *ctx_tb);
static void xtest_dstu7564_512(XtestSt *ctx, TableBuilder *ctx_tb);
static void xtest_dstu7624_ecb_128_128_dec(XtestSt *xtest_ctx, TableBuilder *ctx);
static void xtest_dstu7624_ecb_128_128(XtestSt *xtest_ctx, TableBuilder *ctx);
static void xtest_dstu7624_ecb_128_256(XtestSt *xtest_ctx, TableBuilder *ctx);
static void xtest_dstu7624_ecb_256_256(XtestSt *xtest_ctx, TableBuilder *ctx);
static void xtest_dstu7624_ecb_256_512(XtestSt *xtest_ctx, TableBuilder *ctx);
static void xtest_dstu7624_ecb_512_512(XtestSt *xtest_ctx, TableBuilder *ctx);

void xtest_dstu7624(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    DSTU_generete_data(xtest_ctx);

    xtest_dstu7624_ecb_128_128(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7624_ecb_128_128_dec(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7624_ecb_128_256(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7624_ecb_256_256(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7624_ecb_256_512(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7624_ecb_512_512(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}

static void xtest_dstu7624_ecb_128_128(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna128_128 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_128_128");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::encryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 16)
            ctx_cppcrypto.encrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_128_ba, 16);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_encrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

static void xtest_dstu7624_ecb_128_128_dec(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna128_128 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_DEC_128_128");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::decryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 16)
            ctx_cppcrypto.decrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_128_ba, 16);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_decrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

static void xtest_dstu7624_ecb_128_256(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna128_256 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_128_256");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::encryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 16)
            ctx_cppcrypto.encrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_256_ba, 16);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_encrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

static void xtest_dstu7624_ecb_256_256(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna256_256 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_256_256");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::encryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 32)
            ctx_cppcrypto.encrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_256_ba, 32);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_encrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

static void xtest_dstu7624_ecb_256_512(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna256_512 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_256_512");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::encryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 32)
            ctx_cppcrypto.encrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_512_ba, 32);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_encrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

static void xtest_dstu7624_ecb_512_512(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    Dstu7624Ctx *ctx_cryptonite = NULL;
    kalyna512_512 ctx_cppcrypto;
    uint8_t *crypt_cpp = NULL;
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0, j = 0;
    double time;

    add_mode_name(ctx, "DSTU7624_512_512");

    crypt_cpp = (uint8_t*)malloc(data_size_byte);
    time = get_time();
    ctx_cppcrypto.init(xtest_ctx->CipherType.DSTU.key_data, block_cipher::encryption);
    for (i = 0; i < LOOP_NUM; i++) {
        for(j = 0; j < data_size_byte; j += 64)
            ctx_cppcrypto.encrypt_block(&xtest_ctx->data[j], &crypt_cpp[j]);
    }
    add_time(ctx, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(crypt_cpp, data_size_byte);

    time = get_time();
    ctx_cryptonite = dstu7624_alloc(DSTU7624_SBOX_1);
    dstu7624_init_ecb(ctx_cryptonite, xtest_ctx->CipherType.DSTU.key_512_ba, 64);
    for (i = 0; i < LOOP_NUM; i++) {
        ba_free(res_cryptonite);
        dstu7624_encrypt(ctx_cryptonite, xtest_ctx->data_ba, &res_cryptonite);
    }
    add_time(ctx, time, CRYPTONITE_DSTU);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx, CRYPTONITE_DSTU);
        add_error(ctx, CPPCRYPTO);
    }

    free(crypt_cpp);
    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7624_free(ctx_cryptonite);
}

void xtest_dstu7564(XtestSt *xtest_ctx, TableBuilder *ctx)
{
    DSTU_generete_data(xtest_ctx);

    xtest_dstu7564_256(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_dstu7564_512(xtest_ctx, ctx);
    xtest_table_print(ctx);

    xtest_alg_free(xtest_ctx);
}

static void xtest_dstu7564_256(XtestSt *ctx, TableBuilder *ctx_tb)
{
    Dstu7564Ctx *ctx_cryptonite = NULL;
    kupyna256 ctx_cppcrypto;
    uint8_t hash_cppcrypto[32];
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0;
    double time;

    add_mode_name(ctx_tb, "DSTU7564_256");

    time = get_time();
    ctx_cryptonite = dstu7564_alloc(DSTU7564_SBOX_1);
    dstu7564_init(ctx_cryptonite, 32);
    for (i = 0; i < LOOP_NUM; i++) {
        dstu7564_update(ctx_cryptonite, ctx->data_ba);
    }
    dstu7564_final(ctx_cryptonite, &res_cryptonite);
    add_time(ctx_tb, time, CRYPTONITE_DSTU);

    time = get_time();
    ctx_cppcrypto.init();
    for (i = 0; i < LOOP_NUM; i++) {
        ctx_cppcrypto.update(ctx->data, data_size_byte);
    }
    ctx_cppcrypto.final(hash_cppcrypto);
    add_time(ctx_tb, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(hash_cppcrypto, 32);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx_tb, CRYPTONITE_DSTU);
        add_error(ctx_tb, CPPCRYPTO);
    }

    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7564_free(ctx_cryptonite);
}

static void xtest_dstu7564_512(XtestSt *ctx, TableBuilder *ctx_tb)
{
    Dstu7564Ctx *ctx_cryptonite = NULL;
    kupyna512 ctx_cppcrypto;
    uint8_t hash_cppcrypto[64];
    ByteArray *res_cryptonite = NULL;
    ByteArray *res_cppcrypto = NULL;
    size_t i = 0;
    double time;

    add_mode_name(ctx_tb, "DSTU7564_512");

    time = get_time();
    ctx_cryptonite = dstu7564_alloc(DSTU7564_SBOX_1);
    dstu7564_init(ctx_cryptonite, 64);
    for (i = 0; i < LOOP_NUM; i++) {
        dstu7564_update(ctx_cryptonite, ctx->data_ba);
    }
    dstu7564_final(ctx_cryptonite, &res_cryptonite);
    add_time(ctx_tb, time, CRYPTONITE_DSTU);

    time = get_time();
    ctx_cppcrypto.init();
    for (i = 0; i < LOOP_NUM; i++) {
        ctx_cppcrypto.update(ctx->data, data_size_byte);
    }
    ctx_cppcrypto.final(hash_cppcrypto);
    add_time(ctx_tb, time, CPPCRYPTO);

    res_cppcrypto = ba_alloc_from_uint8(hash_cppcrypto, 64);

    if (!equals_ba(res_cppcrypto, res_cryptonite)) {
        add_error(ctx_tb, CRYPTONITE_DSTU);
        add_error(ctx_tb, CPPCRYPTO);
    }

    ba_free(res_cryptonite);
    ba_free(res_cppcrypto);
    dstu7564_free(ctx_cryptonite);
}
