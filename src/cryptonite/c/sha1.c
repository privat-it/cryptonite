/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stddef.h>
#include <memory.h>

#include "sha1.h"

#include "byte_utils_internal.h"
#include "byte_array_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/sha1.c"

#define SCHEDULE(i)                                                             \
    temp = schedule[(i - 3) & 0xF] ^ schedule[(i - 8) & 0xF]^               \
               schedule[(i - 14) & 0xF] ^ schedule[(i - 16) & 0xF];             \
    schedule[i & 0xF] = temp << 1 | temp >> 31;

#define ROUND0a(a, b, c, d, e, i)                                               \
    schedule[i] = (block[i] << 24) | ((block[i] & 0xFF00) << 8) |           \
                      ((block[i] >> 8) & 0xFF00) | (block[i] >> 24);            \
    ROUNDTAIL(a, b, e, ((b & c) | (~b & d)), i, 0x5A827999)

#define ROUND0b(a, b, c, d, e, i)                                               \
    SCHEDULE(i)                                                             \
    ROUNDTAIL(a, b, e, ((b & c) | (~b & d)), i, 0x5A827999)

#define ROUND1(a, b, c, d, e, i)                                                \
    SCHEDULE(i)                                                             \
    ROUNDTAIL(a, b, e, (b ^ c ^ d), i, 0x6ED9EBA1)

#define ROUND2(a, b, c, d, e, i)                                                \
    SCHEDULE(i)                                                             \
    ROUNDTAIL(a, b, e, ((b & c) ^ (b & d) ^ (c & d)), i, 0x8F1BBCDC)

#define ROUND3(a, b, c, d, e, i)                                                \
    SCHEDULE(i)                                                             \
    ROUNDTAIL(a, b, e, (b ^ c ^ d), i, 0xCA62C1D6)

#define ROUNDTAIL(a, b, e, f, i, k)                                             \
        e += ((((a << 5 | a >> 27) + f) + k) + schedule[i & 0xF]);              \
        b = b << 30 | b >> 2;

#define OUTPUT_TRANSFORM(u32, u8)                       \
        u8[0] =  (uint8_t)(u32[0] >> 24);               \
        u8[1] =  (uint8_t)(u32[0] >> 16);               \
        u8[2] =  (uint8_t)(u32[0] >> 8 );               \
        u8[3] =  (uint8_t)(u32[0] >> 0 );               \
        u8[4] =  (uint8_t)(u32[1] >> 24);               \
        u8[5] =  (uint8_t)(u32[1] >> 16);               \
        u8[6] =  (uint8_t)(u32[1] >> 8 );               \
        u8[7] =  (uint8_t)(u32[1] >> 0 );               \
        u8[8] =  (uint8_t)(u32[2] >> 24);               \
        u8[9] =  (uint8_t)(u32[2] >> 16);               \
        u8[10] = (uint8_t)(u32[2] >> 8 );               \
        u8[11] = (uint8_t)(u32[2] >> 0 );               \
        u8[12] = (uint8_t)(u32[3] >> 24);               \
        u8[13] = (uint8_t)(u32[3] >> 16);               \
        u8[14] = (uint8_t)(u32[3] >> 8 );               \
        u8[15] = (uint8_t)(u32[3] >> 0 );               \
        u8[16] = (uint8_t)(u32[4] >> 24);               \
        u8[17] = (uint8_t)(u32[4] >> 16);               \
        u8[18] = (uint8_t)(u32[4] >> 8 );               \
        u8[19] = (uint8_t)(u32[4] >> 0 )

#define ROUND0a_UNROLL(i)                     \
        ROUND0a(a, b, c, d, e, (0 + i));      \
        ROUND0a(e, a, b, c, d, (1 + i));      \
        ROUND0a(d, e, a, b, c, (2 + i));      \
        ROUND0a(c, d, e, a, b, (3 + i));      \
        ROUND0a(b, c, d, e, a, (4 + i))

#define ROUND0b_UNROLL                        \
        ROUND0a(a, b, c, d, e, 15);           \
        ROUND0b(e, a, b, c, d, 16);           \
        ROUND0b(d, e, a, b, c, 17);           \
        ROUND0b(c, d, e, a, b, 18);           \
        ROUND0b(b, c, d, e, a, 19)

#define ROUND1_UNROLL(i)                      \
        ROUND1(a, b, c, d, e, (20 + i));      \
        ROUND1(e, a, b, c, d, (21 + i));      \
        ROUND1(d, e, a, b, c, (22 + i));      \
        ROUND1(c, d, e, a, b, (23 + i));      \
        ROUND1(b, c, d, e, a, (24 + i))

#define ROUND2_UNROLL(i)                      \
        ROUND2(a, b, c, d, e, (40 + i));      \
        ROUND2(e, a, b, c, d, (41 + i));      \
        ROUND2(d, e, a, b, c, (42 + i));      \
        ROUND2(c, d, e, a, b, (43 + i));      \
        ROUND2(b, c, d, e, a, (44 + i))

#define ROUND3_UNROLL(i)                      \
        ROUND3(a, b, c, d, e, (60 + i));      \
        ROUND3(e, a, b, c, d, (61 + i));      \
        ROUND3(d, e, a, b, c, (62 + i));      \
        ROUND3(c, d, e, a, b, (63 + i));      \
        ROUND3(b, c, d, e, a, (64 + i))

struct Sha1Ctx_st {
    uint8_t msg_last_block[64];
    uint32_t state[5];
    size_t rem;
    size_t msg_tot_len;
    uint8_t k_opad[64];
};

__inline static void sha1_compress(uint32_t *state, uint8_t *block8)
{
    uint32_t block[16];

    uint8_to_uint32(block8, 64, block, 16);

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    uint32_t schedule[16];
    uint32_t temp;

    ROUND0a_UNROLL(0);
    ROUND0a_UNROLL(5);
    ROUND0a_UNROLL(10);

    ROUND0b_UNROLL;

    ROUND1_UNROLL(0);
    ROUND1_UNROLL(5);
    ROUND1_UNROLL(10);
    ROUND1_UNROLL(15);

    ROUND2_UNROLL(0);
    ROUND2_UNROLL(5);
    ROUND2_UNROLL(10);
    ROUND2_UNROLL(15);

    ROUND3_UNROLL(0);
    ROUND3_UNROLL(5);
    ROUND3_UNROLL(10);
    ROUND3_UNROLL(15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    uint32_to_uint8(block, 16, block8, 64);
}

static __inline int sha1_init(Sha1Ctx *ctx)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    memset(ctx->msg_last_block, 0, 64);
    /*Init data from standart.*/
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->rem = 0;
    ctx->msg_tot_len = 0;

cleanup:

    return ret;
}

Sha1Ctx *sha1_alloc(void)
{
    Sha1Ctx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(Sha1Ctx));
    DO(sha1_init(ctx));

cleanup:

    if (ret != RET_OK) {
        sha1_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

Sha1Ctx *sha1_copy_with_alloc(const Sha1Ctx *ctx)
{
    Sha1Ctx *out = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(out, sizeof(Sha1Ctx));
    memcpy(out, ctx, sizeof(Sha1Ctx));

cleanup:

    return out;
}

int sha1_update(Sha1Ctx *ctx, const ByteArray *msg_ba)
{
    uint8_t *msg_buf = NULL;
    uint8_t *shifted_buf;
    size_t msg_buf_size;
    size_t i;
    size_t summ;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(msg_ba != NULL);

    msg_buf = msg_ba->buf;
    msg_buf_size = msg_ba->len;

    ctx->msg_tot_len += msg_buf_size;
    summ = ctx->rem + msg_buf_size;
    if (summ < 64) {
        memcpy(&ctx->msg_last_block[ctx->rem], msg_buf, msg_buf_size);
        ctx->rem += msg_buf_size;
        goto cleanup;
    }

    memcpy(&ctx->msg_last_block[ctx->rem], msg_buf, 64 - ctx->rem);
    sha1_compress(ctx->state, ctx->msg_last_block);
    memset(ctx->msg_last_block, 0, 64);

    shifted_buf = msg_buf + (64 - ctx->rem);
    msg_buf_size -= (64 - ctx->rem);
    for (i = 0; i + 64 <= msg_buf_size; i += 64) {
        sha1_compress(ctx->state, shifted_buf + i);
    }

    ctx->rem = msg_buf_size - i;
    if (ctx->rem != 0) {
        memcpy(ctx->msg_last_block, shifted_buf + i, ctx->rem);
    }

cleanup:

    return ret;
}

int sha1_final(Sha1Ctx *ctx, ByteArray **hash_code)
{
    size_t i;
    size_t rem;
    uint64_t wlen;
    ByteArray *ans = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash_code != NULL);

    rem = ctx->rem;
    ctx->msg_last_block[rem] = 0x80;
    rem++;

    if (64 - rem >= 8) {
        memset(&ctx->msg_last_block[rem], 0, 56 - rem);
    } else {
        memset(&ctx->msg_last_block[rem], 0, 64 - rem);
        sha1_compress(ctx->state, ctx->msg_last_block);
        memset(&ctx->msg_last_block[0], 0, 56);
    }

    wlen = ((uint64_t) ctx->msg_tot_len) << 3;
    for (i = 0; i < 8; i++) {
        ctx->msg_last_block[64 - 1 - i] = (uint8_t) (wlen >> (i << 3));
    }

    sha1_compress(ctx->state, ctx->msg_last_block);

    OUTPUT_TRANSFORM(ctx->state, ctx->msg_last_block);

    CHECK_NOT_NULL(ans = ba_alloc_from_uint8(ctx->msg_last_block, 20));
    memset(ctx->msg_last_block, 0, 64);
    DO(sha1_init(ctx));

    *hash_code = ans;
    ans = NULL;

cleanup:

    ba_free(ans);

    return ret;
}

void sha1_free(Sha1Ctx *ctx)
{
    if (ctx != NULL) {
        free(ctx);
    }
}
