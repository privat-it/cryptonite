/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <string.h>

#include "dsa.h"
#include "macros_internal.h"
#include "math_int_internal.h"
#include "math_gfp_internal.h"
#include "sha1.h"
#include "sha2.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/dsa.c"

typedef struct DsaParamsCtx_st {
    GfpCtx *gfp;
    GfpCtx *gfq;
    WordArray *g; /**< Элемент простого конечного поля GF(p). */
    size_t len;
} DsaParamsCtx;

struct DsaCtx_st {
    DsaParamsCtx *params; /* Параметры DSA. */
    PrngCtx *prng; /* Контекст ГПСЧ. */
    WordArray *priv_key; /* закрытый ключ. */
    WordArray *pub_key; /* открытый ключ. */
    bool sign_status; /* Готов ли контекст для формирования подписи. */
    bool verify_status; /* Готов ли контекст для проверки подписи. */
};

typedef struct DsaShaCtx_st {
    bool is_sha2;

    union {
        Sha1Ctx *sha1;
        Sha2Ctx *sha2;
    } ctx;
} DsaShaCtx;

static int hash(DsaShaCtx *ctx, const void *src, size_t seed_len, uint8_t *hash)
{
    int ret = RET_OK;
    ByteArray *bhash = NULL;
    ByteArray tmp;
    tmp.buf = (uint8_t *) src;
    tmp.len = seed_len;

    if (!ctx->is_sha2) {
        DO(sha1_update(ctx->ctx.sha1, &tmp));
    } else {
        DO(sha2_update(ctx->ctx.sha2, &tmp));
    }

    if (!ctx->is_sha2) {
        DO(sha1_final(ctx->ctx.sha1, &bhash));
    } else {
        DO(sha2_final(ctx->ctx.sha2, &bhash));
    }

    memcpy(hash, bhash->buf, bhash->len);

cleanup:

    ba_free(bhash);

    return ret;
}

static void inc_be(void *src, int len)
{
    int i;
    uint8_t *buffer = src;

    for (i = len - 1; i >= 0; --i) {
        buffer[i] = (buffer[i] + 1) & 0xff;
        if (buffer[i] != 0) {
            break;
        }
    }
}

static int generate_p_q(int L, int N, PrngCtx *prng, ByteArray **p, ByteArray **q)
{
    PrngCtx *random = NULL;
    ByteArray *prng_seed = NULL;
    uint8_t *w = NULL;
    ByteArray *seed_ba = NULL;
    uint8_t *seed = NULL;
    uint8_t *seed1 = NULL;
    uint8_t *offset = NULL;
    uint8_t *u = NULL;
    uint8_t *part1 = NULL;
    uint8_t *part2 = NULL;
    WordArray *one = NULL;
    WordArray *c = NULL;
    WordArray *wq = NULL;
    WordArray *wx = NULL;
    WordArray *wq2 = NULL;
    WordArray *wp = NULL;
    int i, counter;
    int ret = RET_OK;
    int seed_len = 0;
    int hash_bytes_len = 0;
    int w_len = L / 8;
    int n = (L - 1) / N;
    int dsa_hashpart = 0;
    bool is_prime = false;
    DsaShaCtx *sha_ctx = NULL;

    CHECK_PARAM(L >= 512);
    CHECK_PARAM(L % 8 == 0);

    CHECK_NOT_NULL(prng_seed = ba_alloc_by_len(128));

    switch (N) {
    case 160:
        CALLOC_CHECKED(sha_ctx, sizeof(DsaShaCtx));
        CHECK_NOT_NULL(sha_ctx->ctx.sha1 = sha1_alloc());
        sha_ctx->is_sha2 = false;
        hash_bytes_len = 20;
        break;
    case 224:
        CALLOC_CHECKED(sha_ctx, sizeof(DsaShaCtx));
        CHECK_NOT_NULL(sha_ctx->ctx.sha2 = sha2_alloc(SHA2_VARIANT_224));
        sha_ctx->is_sha2 = true;
        hash_bytes_len = 28;
        break;
    case 256:
        CALLOC_CHECKED(sha_ctx, sizeof(DsaShaCtx));
        CHECK_NOT_NULL(sha_ctx->ctx.sha2 = sha2_alloc(SHA2_VARIANT_256));
        sha_ctx->is_sha2 = true;
        hash_bytes_len = 32;
        break;
    default:
        CHECK_PARAM(false);
    }

    /* seed_len >= hash_len */
    seed_len = N / 8;
    MALLOC_CHECKED(seed, seed_len);
    CHECK_NOT_NULL(seed_ba = ba_alloc_by_len(seed_len));
    MALLOC_CHECKED(seed1, seed_len);
    MALLOC_CHECKED(offset, seed_len);
    MALLOC_CHECKED(part1, hash_bytes_len);
    MALLOC_CHECKED(part2, hash_bytes_len);
    memset(part2, 0, hash_bytes_len);
    MALLOC_CHECKED(w, w_len * sizeof (uint8_t));
    MALLOC_CHECKED(u, hash_bytes_len);
    CHECK_NOT_NULL(one = wa_alloc_with_one(WA_LEN_FROM_BITS(L)));
    CHECK_NOT_NULL(wp = wa_alloc(WA_LEN_FROM_BITS(L)));
    CHECK_NOT_NULL(c = wa_alloc(WA_LEN_FROM_BITS(L) / 2));

    DO(prng_next_bytes(prng, prng_seed));

    CHECK_NOT_NULL(random = prng_alloc(PRNG_MODE_DEFAULT, prng_seed));

    while (true) {
        DO(prng_next_bytes(prng, seed_ba));
        DO(hash(sha_ctx, seed_ba->buf, seed_ba->len, part1));

        memcpy(seed1, seed, seed_len);
        inc_be(seed1, seed_len);
        DO(hash(sha_ctx, seed1, seed_len, part2));

        for (i = 0; i != hash_bytes_len; i++) {
            u[i] = (part1[i] ^ part2[i]);
        }

        u[0] |= 0x80;
        u[hash_bytes_len - 1] |= 0x01;
        wa_free(wq);
        CHECK_NOT_NULL(wq = wa_alloc_from_be(u, hash_bytes_len));
        DO(int_is_prime(wq, &is_prime));

        if (!is_prime) {
            continue;
        }

        memcpy(offset, seed, seed_len);
        inc_be(offset, seed_len);

        for (counter = 0; counter < 4096; ++counter) {

            int k;

            for (k = 0; k < n; k++) {
                inc_be(offset, seed_len);
                DO(hash(sha_ctx, offset, seed_len, part1));

                memcpy(w + (w_len - (k + 1) * hash_bytes_len), part1, hash_bytes_len);
            }

            inc_be(offset, seed_len);
            DO(hash(sha_ctx, offset, seed_len, part1));

            dsa_hashpart = w_len - n * hash_bytes_len;

            memcpy(w, &part1[hash_bytes_len - dsa_hashpart], dsa_hashpart);
            w[0] |= 0x80;

            wa_free(wx);
            CHECK_NOT_NULL(wx = wa_alloc_from_be(w, w_len));
            wa_free(wq2);
            CHECK_NOT_NULL(wq2 = wa_copy_with_alloc(wq));
            wa_change_len(c, wx->len >> 1);
            wa_change_len(wq2, wx->len >> 1);

            int_lshift(wq2, 1, wq2);

            int_div(wx, wq2, NULL, c);
            wa_change_len(c, WA_LEN_FROM_BITS(L));

            wa_copy(c, wp);
            int_sub(wp, one, wp);
            int_sub(wx, wp, wp);

            if ((int)int_bit_len(wp) != L) {
                continue;
            }

            DO(int_is_prime(wp, &is_prime));
            if (is_prime) {
                CHECK_NOT_NULL(*p = wa_to_ba(wp));
                CHECK_NOT_NULL(*q = wa_to_ba(wq));
                goto cleanup;
            }
        }
    }

cleanup:

    free(w);
    free(seed);
    free(seed1);
    free(offset);
    free(u);
    free(part1);
    free(part2);
    wa_free(one);
    wa_free(c);
    wa_free(wq);
    wa_free(wx);
    wa_free(wq2);
    wa_free(wp);
    ba_free(seed_ba);
    ba_free(prng_seed);
    if (sha_ctx) {
        if (sha_ctx->is_sha2) {
            sha2_free(sha_ctx->ctx.sha2);
        } else {
            sha1_free(sha_ctx->ctx.sha1);
        }
        free(sha_ctx);
    }

    prng_free(random);

    return ret;
}

static int generate_g(const ByteArray *p, const ByteArray *q, PrngCtx *prng, ByteArray **g)
{
    int ret = RET_OK;
    WordArray *wp = NULL;
    WordArray *e = NULL;
    WordArray *pSub2 = NULL;
    WordArray *h = NULL;
    WordArray *qD = NULL;
    WordArray *wg = NULL;
    WordArray *one = NULL;
    WordArray *two = NULL;
    GfpCtx *gfp = NULL;

    CHECK_NOT_NULL(wp = wa_alloc_from_ba(p));
    CHECK_NOT_NULL(e = wa_alloc(wp->len));
    CHECK_NOT_NULL(pSub2 = wa_alloc(wp->len));
    CHECK_NOT_NULL(h = wa_alloc(wp->len));
    CHECK_NOT_NULL(wg = wa_alloc(wp->len));
    CHECK_NOT_NULL(one = wa_alloc_with_one(wp->len));
    CHECK_NOT_NULL(two = wa_alloc_with_zero(wp->len));
    two->buf[0] = 2;
    CHECK_NOT_NULL(gfp = gfp_alloc(wp));

    int_sub(wp, one, e);
    CHECK_NOT_NULL(qD = wa_alloc_from_ba(q));
    wa_change_len(qD, wp->len / 2);
    int_div(e, qD, e, NULL);
    int_sub(wp, two, pSub2);

    while (true) {
        DO(int_rand(prng, pSub2, h));

        gfp_mod_pow(gfp, h, e, wg);

        if (int_bit_len(wg) > 1) {
            break;
        }
    }

    CHECK_NOT_NULL(*g = wa_to_ba(wg));
cleanup:
    wa_free(wp);
    wa_free(e);
    wa_free(pSub2);
    wa_free(h);
    wa_free(qD);
    wa_free(one);
    wa_free(two);
    gfp_free(gfp);
    wa_free(wg);

    return ret;
}

/**
 * @params l битовая длина p
 * @params n битовая длина q
 */
DsaCtx *dsa_alloc_ext(int l, int n, PrngCtx *prng)
{
    DsaCtx *ctx = NULL;
    ByteArray *p = NULL;
    ByteArray *q = NULL;
    ByteArray *g = NULL;
    int ret = RET_OK;

    CHECK_PARAM(prng != NULL);

    DO(generate_p_q(l, n, prng, &p, &q));
    DO(generate_g(p, q, prng, &g));

    CHECK_NOT_NULL(ctx = dsa_alloc(p, q, g));

cleanup:

    ba_free(p);
    ba_free(q);
    ba_free(g);

    return ctx;
}

DsaCtx *dsa_alloc(const ByteArray *p, const ByteArray *q, const ByteArray *g)
{
    DsaCtx *ctx = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    size_t len;
    DsaParamsCtx *params = NULL;
    int ret = RET_OK;

    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(g != NULL);

    CALLOC_CHECKED(ctx, sizeof (DsaCtx));
    CALLOC_CHECKED(params, sizeof (DsaParamsCtx));

    CHECK_NOT_NULL(wp = wa_alloc_from_ba(p));
    len = WA_LEN_FROM_BITS(int_bit_len(wp));
    wa_change_len(wp, len);
    CHECK_NOT_NULL(params->gfp = gfp_alloc(wp));
    CHECK_NOT_NULL(wq = wa_alloc_from_ba(q));
    wa_change_len(wq, len);
    CHECK_NOT_NULL(params->gfq = gfp_alloc(wq));
    CHECK_NOT_NULL(params->g = wa_alloc_from_ba(g));
    wa_change_len(params->g, len);

    params->len = len;

    ctx->params = params;
    ctx->prng = NULL;
    ctx->priv_key = NULL;
    ctx->pub_key = NULL;
    ctx->sign_status = false;
    ctx->verify_status = false;

cleanup:

    wa_free(wp);
    wa_free(wq);

    return ctx;
}

int dsa_get_params(const DsaCtx *ctx, ByteArray **p, ByteArray **q, ByteArray **g)
{
    size_t plen;
    size_t qlen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(g != NULL);

    plen = (int_bit_len(ctx->params->gfp->p) + 7) / 8;
    qlen = (int_bit_len(ctx->params->gfq->p) + 7) / 8;

    CHECK_NOT_NULL(*p = wa_to_ba(ctx->params->gfp->p));
    DO(ba_change_len(*p, plen));

    CHECK_NOT_NULL(*q = wa_to_ba(ctx->params->gfq->p));
    DO(ba_change_len(*q, qlen));

    CHECK_NOT_NULL(*g = wa_to_ba(ctx->params->g));
    DO(ba_change_len(*g, plen));

cleanup:

    return ret;
}

int dsa_generate_privkey(const DsaCtx *ctx, PrngCtx *prng, ByteArray **priv_key)
{
    WordArray *wd = NULL;
    int ret = RET_OK;
    size_t blen;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(priv_key != NULL);

    CHECK_NOT_NULL(wd = wa_alloc(ctx->params->gfq->p->len));

    DO(int_rand(prng, ctx->params->gfq->p, wd));

    CHECK_NOT_NULL(*priv_key = wa_to_ba(wd));
    blen = (int_bit_len(ctx->params->gfq->p) + 7) / 8;
    DO(ba_change_len(*priv_key, blen));

cleanup:

    wa_free_private(wd);

    return ret;
}

int dsa_get_pubkey(const DsaCtx *ctx, const ByteArray *priv_key, ByteArray **pub_key)
{
    size_t blen;
    WordArray *d = NULL;
    WordArray *r = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(priv_key != NULL);
    CHECK_PARAM(pub_key != NULL);

    CHECK_NOT_NULL(d = wa_alloc_from_ba(priv_key));
    if (int_is_zero(d) || int_cmp(d, ctx->params->gfq->p) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(d, ctx->params->gfp->p->len);
    CHECK_NOT_NULL(r = wa_alloc(ctx->params->gfp->p->len));
    gfp_mod_pow(ctx->params->gfp, ctx->params->g, d, r);

    blen = (int_bit_len(ctx->params->gfp->p) + 7) / 8;
    CHECK_NOT_NULL(*pub_key = wa_to_ba(r));
    DO(ba_change_len(*pub_key, blen));

cleanup:

    wa_free(r);
    wa_free_private(d);

    return ret;
}

int dsa_init_sign(DsaCtx *ctx, const ByteArray *priv_key, PrngCtx *prng)
{
    ByteArray *seed = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(priv_key != NULL);
    CHECK_PARAM(prng != NULL);

    CHECK_NOT_NULL(ctx->priv_key = wa_alloc_from_ba(priv_key));
    wa_free(ctx->pub_key);
    ctx->pub_key = NULL;

    /* Проверка корректности закрытого ключа. */
    if (int_is_zero(ctx->priv_key) || (int_cmp(ctx->priv_key, ctx->params->gfq->p) >= 0)) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    CHECK_NOT_NULL(seed = ba_alloc_by_len(128));
    wa_change_len(ctx->priv_key, ctx->params->gfq->p->len);

    /* Установка датчика псевдослучайных чисел. */
    DO(prng_next_bytes(prng, seed));

    if (ctx->prng != NULL) {
        DO(prng_seed(ctx->prng, seed));
    } else {
        CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    }

    ctx->sign_status = true;

cleanup:

    ba_free(seed);
    if (ret != RET_OK) {
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    return ret;
}

int dsa_sign(const DsaCtx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s)
{
    WordArray *z = NULL;
    WordArray *k = NULL;
    WordArray *k_inv = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *t = NULL;
    WordArray *q2 = NULL;
    int ret = RET_OK;
    const DsaParamsCtx *params;
    const WordArray *q;
    size_t len;
    size_t q_byte_len;
    size_t rs_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    params = ctx->params;
    q = params->gfq->p;
    len = params->len;

    /* z = the leftmost min(bit_len(q), bit_len(Hash(M))) bits of Hash(M). */
    CHECK_NOT_NULL(z = wa_alloc_from_be(hash->buf, hash->len));
    q_byte_len = (int_bit_len(q) + 7) / 8;
    if (hash->len > q_byte_len) {
        int_rshift(0, z, (hash->len - q_byte_len) * 8, z);
    }
    wa_change_len(z, q->len);

    CHECK_NOT_NULL(k = wa_alloc(q->len));
    CHECK_NOT_NULL(t = wa_alloc(len));
    CHECK_NOT_NULL(q2 = wa_copy_with_alloc(q));
    wa_change_len(q2, len / 2);

    CHECK_NOT_NULL(wr = wa_alloc(q->len));
    CHECK_NOT_NULL(ws = wa_alloc(q->len));

    do {
        wa_change_len(wr, len / 2);
        do {
            /* Случайное число k (0 < k < q). */
            DO(int_rand(ctx->prng, q, k));
            /* r = (a^k mod p) mod q. */
            gfp_mod_pow(params->gfp, params->g, k, t);
            int_div(t, q2, NULL, wr);

        } while (int_is_zero(wr));

        /* s = k^(-1)(z + x*r) mod q */
        k_inv = gfp_mod_inv(params->gfq, k);
        if (k_inv == NULL) {
            continue;
        }

        wa_change_len(wr, q->len);
        gfp_mod_mul(params->gfq, ctx->priv_key, wr, ws);
        gfp_mod_add(params->gfq, ws, z, ws);
        gfp_mod_mul(params->gfq, k_inv, ws, ws);
        wa_free_private(k_inv);
        k_inv = NULL;

    } while (int_is_zero(ws));

    rs_len = (int_bit_len(q) + 7) >> 3;

    CHECK_NOT_NULL(*r = wa_to_ba(wr));
    DO(ba_change_len(*r, rs_len));

    CHECK_NOT_NULL(*s = wa_to_ba(ws));
    DO(ba_change_len(*s, rs_len));

cleanup:

    wa_free(z);
    wa_free_private(k);
    wa_free_private(k_inv);
    wa_free(wr);
    wa_free(ws);
    wa_free(t);
    wa_free(q2);

    return ret;
}

int dsa_init_verify(DsaCtx *ctx, const ByteArray *pub_key)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(pub_key != NULL);

    wa_free_private(ctx->priv_key);
    ctx->priv_key = NULL;

    if (ctx->prng != NULL) {
        prng_free(ctx->prng);
        ctx->prng = NULL;
    }

    CHECK_NOT_NULL(ctx->pub_key = wa_alloc_from_ba(pub_key));
    wa_change_len(ctx->pub_key, ctx->params->gfp->p->len);

    ctx->verify_status = true;

cleanup:

    return ret;
}

int dsa_verify(const DsaCtx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s)
{
    WordArray *z = NULL;
    WordArray *u1 = NULL;
    WordArray *u2 = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *w = NULL;
    WordArray *t = NULL;
    WordArray *q2 = NULL;
    int ret = RET_OK;
    const DsaParamsCtx *params;
    const WordArray *q;
    size_t len;
    size_t q_byte_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    params = ctx->params;
    q = params->gfq->p;
    len = params->len;

    /* 0 < r < q, 0 < s < q */
    CHECK_NOT_NULL(wr = wa_alloc_from_ba(r));
    CHECK_NOT_NULL(ws = wa_alloc_from_ba(s));

    if (int_is_zero(wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if (int_cmp(wr, ctx->params->gfq->p) >= 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if (int_is_zero(ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if (int_cmp(ws, ctx->params->gfq->p) >= 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    wa_change_len(wr, ctx->params->gfq->p->len);
    wa_change_len(ws, ctx->params->gfq->p->len);

    /* z = the leftmost min(bit_len(q), bit_len(Hash(M))) bits of Hash(M). */
    CHECK_NOT_NULL(z = wa_alloc_from_be(hash->buf, hash->len));
    q_byte_len = (int_bit_len(q) + 7) / 8;
    if (hash->len > q_byte_len) {
        int_rshift(0, z, (hash->len - q_byte_len) * 8, z);
    }
    wa_change_len(z, q->len);

    /* w = s^(-1) (mod q). */
    CHECK_NOT_NULL(w = gfp_mod_inv(params->gfq, ws));
    /* u1 = h*w (mod q) */
    CHECK_NOT_NULL(u1 = wa_alloc(q->len));
    gfp_mod_mul(params->gfq, w, z, u1);

    /* u2 = r*w (mod q). */
    CHECK_NOT_NULL(u2 = wa_alloc(q->len));
    gfp_mod_mul(params->gfq, w, wr, u2);

    /* s = (a^u1 * pub_key^u2 (mod p)) (mod q). */
    CHECK_NOT_NULL(t = wa_alloc(len));
    gfp_mod_dual_pow(ctx->params->gfp, ctx->params->g, u1, ctx->pub_key, u2, t);

    CHECK_NOT_NULL(q2 = wa_copy_with_alloc(q));
    wa_change_len(q2, len / 2);
    wa_change_len(ws, len / 2);
    int_div(t, q2, NULL, ws);

    if (!int_equals(wr, ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(z);
    wa_free(u1);
    wa_free(u2);
    wa_free(wr);
    wa_free(ws);
    wa_free(w);
    wa_free(t);
    wa_free(q2);

    return ret;
}

static void dsa_params_free(DsaParamsCtx *params)
{
    if (params != NULL) {
        gfp_free(params->gfp);
        gfp_free(params->gfq);
        wa_free(params->g);
        free(params);
    }
}

void dsa_free(DsaCtx *ctx)
{
    if (ctx != NULL) {
        wa_free_private(ctx->priv_key);
        dsa_params_free(ctx->params);
        prng_free(ctx->prng);
        wa_free(ctx->pub_key);
        free(ctx);
    }
}
