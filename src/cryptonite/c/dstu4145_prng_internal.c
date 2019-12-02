/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdbool.h>
#ifdef _WIN32
# include <windows.h>
#endif
#include <time.h>
#include <string.h>

#include "dstu4145_prng_internal.h"
#include "gost28147.h"
#include "gost34_311.h"
#include "byte_utils_internal.h"
#include "byte_array_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/dstu4145_prng_internal.c"

struct Dstu4145Prng_st {
    uint32_t time[2];              /* Текущее время. */
    uint32_t state[2];             /* Текущее внутреннее состояние генератора псевдослучайных чисел. */
    uint32_t old_state[2];         /* Начальное значення внутреннего состояния ГПСЧ. */
    Gost28147Ctx
    *ecb;             /* Контекст шифрования в соответствии с ГОСТ 28147-89 в режиме ECB. */
    Gost34311Ctx *hash;
};

int gost28147_ecb_core(Gost28147Ctx *ctx, const uint8_t *src, size_t len, bool is_encrypt, uint8_t *dst);

static uint64_t get_current_time(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
#else
    return (uint64_t)time(NULL);
#endif
}

Dstu4145PrngCtx *dstu4145_prng_alloc(const ByteArray *seed)
{
    Dstu4145PrngCtx *prng = NULL;
    const uint8_t *state;
    uint8_t time[8];
    uint64_t tm;
    ByteArray *key = NULL;
    ByteArray *src = NULL;
    ByteArray *dst = NULL;
    ByteArray *sync = NULL;
    int ret = RET_OK;

    CHECK_PARAM(seed->len >= 40);

    CALLOC_CHECKED(prng, sizeof(Dstu4145PrngCtx));
    CHECK_NOT_NULL(prng->ecb = gost28147_alloc(GOST28147_SBOX_ID_1));

    CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
    DO(ba_set(sync, 0));
    CHECK_NOT_NULL(prng->hash = gost34_311_alloc(GOST28147_SBOX_ID_1, sync));

    state = ((uint8_t *) seed->buf) + 32;
    tm = get_current_time();
    DO(uint64_to_uint8(&tm, 1, time, 8));
    DO(uint8_swap(time, 8, time, 8));

    memcpy(prng->state, state, 8);
    memcpy(prng->old_state, state, 8);

    CHECK_NOT_NULL(key = ba_alloc_from_uint8(seed->buf, 32));
    CHECK_NOT_NULL(src = ba_alloc_from_uint8(time, 8));

    DO(gost28147_init_ecb(prng->ecb, key));
    DO(gost28147_encrypt(prng->ecb, src, &dst));
    DO(ba_to_uint8(dst, (uint8_t *) prng->time, 8));

    tm = 0;
    secure_zero(time, 8);

cleanup:

    if (ret != RET_OK)  {
        free(prng);
        prng = NULL;
    }

    ba_free_private(key);
    ba_free(src);
    ba_free(dst);
    ba_free(sync);

    return prng;
}

static int next_byte(Dstu4145PrngCtx *prng, uint8_t *rnd_byte)
{
    uint8_t rnd = 0;
    uint8_t bit;
    int i;
    int ret = RET_OK;

    for (i = 0; i < 8; i++) {

        prng->state[0] ^= prng->time[0];
        prng->state[1] ^= prng->time[1];

        DO(gost28147_ecb_core(prng->ecb, (uint8_t *)prng->state, 8, true, (uint8_t *)prng->state));

        bit = ((uint8_t *)prng->state)[0] & 1;
        rnd |= bit << i;

        prng->state[0] ^= prng->time[0];
        prng->state[1] ^= prng->time[1];
        DO(gost28147_ecb_core(prng->ecb, (uint8_t *)prng->state, 8, true, (uint8_t *)prng->state));

        /* Зациклился ли генератор? */
        if ((prng->state[0] == prng->old_state[0])
                && (prng->state[1] == prng->old_state[1])) {
            SET_ERROR(RET_DSTU_PRNG_LOOPED);
        }
    }

    memcpy(rnd_byte, &rnd, 1);

cleanup:

    return ret;
}

int dstu4145_prng_seed(Dstu4145PrngCtx *prng, const ByteArray *buf)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;
    ByteArray *hash1 = NULL;
    ByteArray *hash2 = NULL;
    uint64_t tm;
    uint8_t time[8];
    ByteArray *key = NULL;
    ByteArray *src = NULL;
    ByteArray *dst = NULL;

    CHECK_PARAM(buf != NULL);

    CHECK_NOT_NULL(seed = ba_alloc_by_len(8));

    gost34_311_update(prng->hash, buf);
    ba_from_uint8((uint8_t *)prng->state, 8, seed);
    gost34_311_update(prng->hash, seed);
    ba_from_uint8((uint8_t *)prng->time, 8, seed);
    gost34_311_update(prng->hash, seed);
    gost34_311_final(prng->hash, &hash1);

    gost34_311_update(prng->hash, hash1);
    gost34_311_update(prng->hash, buf);
    ba_from_uint8((uint8_t *)prng->state, 8, seed);
    gost34_311_update(prng->hash, seed);
    ba_from_uint8((uint8_t *)prng->time, 8, seed);
    gost34_311_update(prng->hash, seed);
    gost34_311_final(prng->hash, &hash2);

    tm = get_current_time();
    DO(uint64_to_uint8(&tm, 1, time, 8));
    DO(uint8_swap(time, 8, time, 8));

    memcpy(prng->state, hash2->buf, 8);
    memcpy(prng->old_state, hash2->buf, 8);

    CHECK_NOT_NULL(key = ba_copy_with_alloc(hash1, 0, 32));
    CHECK_NOT_NULL(src = ba_alloc_from_uint8(time, 8));

    DO(gost28147_init_ecb(prng->ecb, key));
    DO(gost28147_encrypt(prng->ecb, src, &dst));
    DO(ba_to_uint8(dst, (uint8_t *)prng->time, 8));

cleanup:

    tm = 0;
    secure_zero(time, 8);
    ba_free_private(key);
    ba_free_private(src);
    ba_free_private(dst);
    ba_free_private(seed);
    ba_free_private(hash1);
    ba_free_private(hash2);

    return ret;
}

int dstu4145_prng_next_bytes(Dstu4145PrngCtx *ctx, ByteArray *buf)
{
    size_t i;
    int ret = RET_OK;

    for (i = 0; i < buf->len; i++) {
        DO(next_byte(ctx, &buf->buf[i]));
    }

cleanup:

    return ret;
}

void dstu4145_prng_free(Dstu4145PrngCtx *ctx)
{
    if (ctx) {
        gost28147_free(ctx->ecb);
        gost34_311_free(ctx->hash);
        secure_zero(ctx, sizeof(Dstu4145PrngCtx));
        free(ctx);
    }
}
