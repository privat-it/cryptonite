/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <memory.h>

#include "rsa.h"
#include "sha1.h"
#include "sha2.h"
#include "math_int_internal.h"
#include "math_gfp_internal.h"
#include "byte_utils_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/rsa.c"

typedef enum {
    RSA_MODE_NONE = 0,
    RSA_MODE_ENCRYPT_PKCS,
    RSA_MODE_DECRYPT_PKCS,
    RSA_MODE_ENCRYPT_OAEP,
    RSA_MODE_DECRYPT_OAEP,
    RSA_MODE_SIGN_PKCS,
    RSA_MODE_VERIFY_PKCS
} RsaMode;

struct RsaCtx_st {
    RsaMode mode_id;
    RsaHashType hash_type;
    PrngCtx *prng;
    ByteArray *label;
    GfpCtx *gfp;
    WordArray *e;
    WordArray *d;
    bool is_inited;
};

/* SHA-1, SHA-256, SHA-384, SHA-512 */
const uint8_t HASH_LEN[] = {20, 32, 48, 64};

const uint8_t HASH_AID_LEN[] = {15, 19, 19, 19};

const uint8_t AID_SHA1[] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
        0x00, 0x04, 0x14
};
const uint8_t AID_SHA256[] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
const uint8_t AID_SHA384[] = {
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
const uint8_t AID_SHA512[] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

const uint8_t LHASH_SHA1[20] = {
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef,
        0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};
const uint8_t LHASH_SHA256[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
        0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};
const uint8_t LHASH_SHA384[48] = {
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
        0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
        0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
        0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};
const uint8_t LHASH_SHA512[64] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50,
        0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c,
        0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e
};

const uint8_t md5_empty_string[] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
const uint8_t ripemd160_empty_string[] = {0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31};
const uint8_t ripemd128_empty_string[] = {0xcd, 0xf2, 0x62, 0x13, 0xa1, 0x50, 0xdc, 0x3e, 0xcb, 0x61, 0x0f, 0x18, 0xf6, 0xb3, 0x8b, 0x46};

static int rsa_hash_alloc(void **ctx, RsaHashType id)
{
    int ret = RET_OK;

    switch (id) {
        case RSA_HASH_SHA1:
        CHECK_NOT_NULL((*ctx) = sha1_alloc());
            break;
        case RSA_HASH_SHA256:
        CHECK_NOT_NULL((*ctx) = sha2_alloc(SHA2_VARIANT_256));
            break;
        case RSA_HASH_SHA384:
        CHECK_NOT_NULL((*ctx) = sha2_alloc(SHA2_VARIANT_384));
            break;
        case RSA_HASH_SHA512:
        CHECK_NOT_NULL((*ctx) = sha2_alloc(SHA2_VARIANT_512));
            break;
        default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    return ret;
}

static int rsa_hash_update(void *ctx, const ByteArray *data, RsaHashType id)
{
    int ret = RET_OK;

    switch (id) {
        case RSA_HASH_SHA1:
        DO(sha1_update((Sha1Ctx *) ctx, data));
            break;
        case RSA_HASH_SHA256:
        case RSA_HASH_SHA384:
        case RSA_HASH_SHA512:
        DO(sha2_update((Sha2Ctx *) ctx, data));
            break;
        default:
        SET_ERROR(RET_INVALID_PARAM);
    }
cleanup:
    return ret;
}

static int rsa_hash_final(void *ctx, ByteArray **hash, RsaHashType id)
{
    int ret = RET_OK;

    switch (id) {
        case RSA_HASH_SHA1:
            DO(sha1_final((Sha1Ctx *) ctx, hash));
            break;
        case RSA_HASH_SHA256:
        case RSA_HASH_SHA384:
        case RSA_HASH_SHA512:
            DO(sha2_final(ctx, hash));
            break;
        default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    return ret;
}

static void rsa_hash_free(void *ctx, RsaHashType id)
{
    int ret = RET_OK;

    switch (id) {
        case RSA_HASH_SHA1:
            sha1_free((Sha1Ctx *) ctx);
            break;
        case RSA_HASH_SHA256:
        case RSA_HASH_SHA384:
        case RSA_HASH_SHA512:
            sha2_free((Sha2Ctx *) ctx);
            break;
        default:
        SET_ERROR(RET_INVALID_PARAM);
    }

cleanup:

    return;
}

static int mgf(RsaHashType htype, const void *seed, uint8_t seed_len, uint8_t *mask, uint8_t mask_len)
{
    ByteArray *bseed = NULL;
    ByteArray *bhash = NULL;
    ByteArray *count = NULL;
    void *hash_ctx = NULL;
    uint8_t hlen = HASH_LEN[htype];
    int iter = 1 + (mask_len - 1) / hlen;
    uint8_t offset = 0;
    const int idx = 3;
    int ret = RET_OK;


    CHECK_NOT_NULL(count = ba_alloc_by_len(4));
    DO(ba_set(count, 0));

    CHECK_NOT_NULL(bseed = ba_alloc_from_uint8(seed, seed_len));

    DO(rsa_hash_alloc(&hash_ctx, htype));
    for (count->buf[idx] = 0; count->buf[idx] < iter; count->buf[idx]++) {
        DO(rsa_hash_update(hash_ctx, bseed, htype));
        DO(rsa_hash_update(hash_ctx, count, htype));
        ba_free(bhash);
        bhash = NULL;
        DO(rsa_hash_final(hash_ctx, &bhash, htype));
        memcpy(mask + offset, bhash->buf, hlen < mask_len - offset ? hlen : mask_len - offset);
        offset += hlen;
    }

cleanup:

    ba_free(bseed);
    ba_free(bhash);
    ba_free(count);
    rsa_hash_free(hash_ctx, htype);

    return ret;
}

static uint8_t *oaep_get_lhash(RsaHashType htype, const ByteArray *label)
{
    uint8_t *hash = NULL;
    ByteArray *hash_ba = NULL;
    void *hash_ctx = NULL;
    int ret = RET_OK;

    if (label == NULL) {
        if (htype == RSA_HASH_SHA1) {
            MALLOC_CHECKED(hash, sizeof(LHASH_SHA1));
            memcpy(hash, LHASH_SHA1, sizeof(LHASH_SHA1));
        } else if (htype == RSA_HASH_SHA256) {
            MALLOC_CHECKED(hash, sizeof(LHASH_SHA256));
            memcpy(hash, LHASH_SHA256, sizeof(LHASH_SHA256));
        } else if (htype == RSA_HASH_SHA384) {
            MALLOC_CHECKED(hash, sizeof(LHASH_SHA384));
            memcpy(hash, LHASH_SHA384, sizeof(LHASH_SHA384));
        } else if (htype == RSA_HASH_SHA512) {
            MALLOC_CHECKED(hash, sizeof(LHASH_SHA512));
            memcpy(hash, LHASH_SHA512, sizeof(LHASH_SHA512));
        }
    } else {
        DO(rsa_hash_alloc(&hash_ctx, htype));
        CHECK_NOT_NULL(hash_ctx);
        DO(rsa_hash_update(hash_ctx, label, htype));
        DO(rsa_hash_final(hash_ctx, &hash_ba, htype));
        MALLOC_CHECKED(hash, hash_ba->len);
        memcpy(hash, ba_get_buf(hash_ba), ba_get_len(hash_ba));
    }

cleanup:
    rsa_hash_free(hash_ctx, htype);
    ba_free(hash_ba);
    if (ret != RET_OK) {
        free(hash);
        hash = NULL;
    }
    return hash;
}

static int rsaedp(const GfpCtx *gfp, const WordArray *x, const WordArray *src, WordArray **dst)
{
    int ret = RET_OK;

    CHECK_NOT_NULL(*dst = wa_alloc(gfp->p->len));
    gfp_mod_pow(gfp, src, x, *dst);

cleanup:

    return ret;
}

static int rsa_encrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *data, ByteArray **out)
{
    uint8_t *m = NULL;
    size_t len;
    size_t off;
    size_t data_len;
    WordArray *wm = NULL;
    WordArray *wout = NULL;
    ByteArray *seed = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id != RSA_MODE_ENCRYPT_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    data_len = ba_get_len(data);

    if (ba_get_len(data) > len - 11) {
        SET_ERROR(RET_DATA_TOO_LONG);
    }

    MALLOC_CHECKED(m, len);

    /* EM = 0x00 || 0x02 || PS || 0x00 || M */
    m[0] = 0;
    m[1] = 2;
    CHECK_NOT_NULL(seed = ba_alloc_by_len(len - data_len - 3));
    DO(prng_next_bytes(ctx->prng, seed));
    ba_to_uint8(seed, m + 2, len - data_len - 3);
    ba_free(seed);
    seed = NULL;
    m[len - data_len - 1] = 0;
    DO(ba_to_uint8(data, m + len - data_len, data_len));

    CHECK_NOT_NULL(seed = ba_alloc_by_len(1));
    off = len - data_len - 2;
    while (off >= 2) {
        if (!m[off]) {
            DO(prng_next_bytes(ctx->prng, seed));
            DO(ba_to_uint8(seed, m + off, 1));
        } else {
            off--;
        }
    }

    CHECK_NOT_NULL(wm = wa_alloc_from_be(m, len));

    rsaedp(ctx->gfp, ctx->e, wm, &wout);

    CHECK_NOT_NULL(*out = wa_to_ba(wout));

cleanup:

    wa_free(wout);
    wa_free(wm);
    ba_free(seed);
    free(m);

    return ret;
}

static int rsa_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *data, ByteArray **out)
{
    uint8_t i;
    uint8_t *m = NULL;
    size_t len;
    WordArray *wdata = NULL;
    WordArray *wm = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(out != NULL);

    if (ctx->mode_id != RSA_MODE_DECRYPT_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    CHECK_NOT_NULL(wdata = wa_alloc_from_ba(data));

    DO(rsaedp(ctx->gfp, ctx->d, wdata, &wm));
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    MALLOC_CHECKED(m, len);
    DO(wa_to_uint8(wm, m, len));
    DO(uint8_swap(m, len, m, len));

    if (m[0] != 0 || m[1] != 2) {
        SET_ERROR(RET_RSA_DECRYPTION_ERROR);
    }

    for (i = 2; (i < len) && (m[i] != 0);) {
        i++;
    }

    i++;

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(m + i, len - i));

cleanup:

    free(m);
    wa_free(wdata);
    wa_free(wm);

    return ret;
}

static int rsa_encrypt_oaep(RsaCtx *ctx, const ByteArray *msg, const ByteArray *L, ByteArray **out)
{
    WordArray *wm = NULL;
    WordArray *wout = NULL;
    uint8_t *em = NULL;
    uint8_t *lhash = NULL;
    uint8_t *masked_seed;
    uint8_t *masked_db;
    ByteArray *seed = NULL;
    size_t len;
    uint8_t i, j;
    uint8_t hlen;
    uint8_t dblen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(msg != NULL);
    CHECK_PARAM(out != NULL);

    hlen = HASH_LEN[ctx->hash_type];
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    dblen = (uint8_t)(len - hlen - 1);

    if (len < (size_t)(2 * hlen + 2)) {
        SET_ERROR(RET_INVALID_CTX);
    }

    if (msg->len > (len - 2 * hlen - 2)) {
        SET_ERROR(RET_DATA_TOO_LONG);
    }


    MALLOC_CHECKED(em, len);

    masked_seed = em + 1;
    masked_db = em + 1 + hlen;

    CHECK_NOT_NULL(lhash = oaep_get_lhash(ctx->hash_type, L));

    /*
     *                     +--------+------+------+-----+
     *                DB = |  lHash |  PS  | 0x01 |  M  |
     *                     +--------+------+------+-----+
     *                                    |
     *          +----------+              V
     *          |   seed   |--> MGF ---> xor
     *          +----------+              |
     *                |                   |
     *       +--+     V                   |
     *       |00|    xor <----- MGF <-----|
     *       +--+     |                   |
     *         |      |                   |
     *         V      V                   V
     *       +--+----------+----------------------------+
     * EM =  |00|maskedSeed|          maskedDB          |
     *       +--+----------+----------------------------+
     */
    em[0] = 0;
    CHECK_NOT_NULL(seed = ba_alloc_by_len(hlen));
    DO(prng_next_bytes(ctx->prng, seed));
    DO(mgf(ctx->hash_type, seed->buf, hlen, masked_db, dblen));

    for (i = 0, j = 0; i < dblen; i++) {
        if (i < hlen) {
            masked_db[i] ^= lhash[i];
        } else if (i == len - msg->len - hlen - 2) {
            masked_db[i] ^= 1;
        } else if (i > len - msg->len - hlen - 2) {
            masked_db[i] ^= msg->buf[j++];
        }
    }
    DO(mgf(ctx->hash_type, masked_db, dblen, masked_seed, hlen));

    for (i = 0; i < hlen; i++) {
        masked_seed[i] ^= seed->buf[i];
    }

    CHECK_NOT_NULL(wm = wa_alloc_from_be(em, len));

    DO(rsaedp(ctx->gfp, ctx->e, wm, &wout));

    CHECK_NOT_NULL(*out = wa_to_ba(wout));

cleanup:

    wa_free(wm);
    wa_free(wout);
    free(em);
    free(lhash);
    ba_free(seed);

    return ret;
}

static int rsa_decrypt_oaep(RsaCtx *ctx, const ByteArray *msg, ByteArray **out)
{
    WordArray *wc = NULL;
    WordArray *wem = NULL;
    uint8_t *em = NULL;
    uint8_t *c = NULL;
    uint8_t *lhash = NULL;
    uint8_t *masked_seed;
    uint8_t *masked_db;
    uint8_t *seed;
    uint8_t *db;
    uint8_t hlen;
    size_t len;
    uint8_t dblen;
    uint8_t moff, i;
    size_t c_len;
    int ret = RET_OK;

    DO(ba_to_uint8_with_alloc(msg, &c, &c_len));
    CHECK_NOT_NULL(c);

    hlen = HASH_LEN[ctx->hash_type];
    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    dblen = (uint8_t)(len - hlen - 1);

    seed = (uint8_t *)c + 1;
    db = (uint8_t *)c + 1 + hlen;
    CHECK_NOT_NULL(lhash = oaep_get_lhash(ctx->hash_type, ctx->label));

    if (len < (size_t)(2 * hlen + 2)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(wc = wa_alloc_from_ba(msg));

    DO(rsaedp(ctx->gfp, ctx->d, wc, &wem));

    MALLOC_CHECKED(em, len);
    DO(wa_to_uint8(wem, em, len));
    DO(uint8_swap(em, len, em, len));

    masked_seed = em + 1;
    masked_db = em + 1 + hlen;

    DO(mgf(ctx->hash_type, masked_db, dblen, seed, hlen));

    for (i = 0; i < hlen; i++) {
        seed[i] ^= masked_seed[i];
    }

    DO(mgf(ctx->hash_type, seed, hlen, db, dblen));

    for (i = 0; i < dblen; i++) {
        db[i] ^= masked_db[i];
    }

    if (memcmp(db, lhash, hlen) || em[0]) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    moff = hlen;
    while ((moff < dblen) && (db[moff] != 0x01)) {
        moff++;
    }
    moff++;

    CHECK_NOT_NULL(*out = ba_alloc_from_uint8(db + moff, dblen - moff));

cleanup:

    wa_free(wc);
    wa_free(wem);
    free(em);
    free(lhash);
    free(c);

    return ret;
}

static const uint8_t *pkcs15_get_aid(RsaHashType htype)
{
    if (htype == RSA_HASH_SHA1) {
        return AID_SHA1;
    } else if (htype == RSA_HASH_SHA256) {
        return AID_SHA256;
    } else if (htype == RSA_HASH_SHA384) {
        return AID_SHA384;
    } else if (htype == RSA_HASH_SHA512) {
        return AID_SHA512;
    }

    return NULL;
}

RsaCtx *rsa_alloc(void)
{
    RsaCtx *ctx = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(ctx, sizeof(RsaCtx));

    ctx->e = NULL;
    ctx->d = NULL;
    ctx->gfp = NULL;
    ctx->hash_type = 0;
    ctx->prng = 0;

cleanup:

    return ctx;
}

static int rsa_gen_privkey_core(RsaCtx *ctx, PrngCtx *prng, const size_t bits, const ByteArray *e,
                                WordArray **wa_p, WordArray **wa_q, WordArray **wa_fi,
                                WordArray **wa_n, WordArray **wa_d)
{
    WordArray *fi = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wsub_p_q = NULL;
    WordArray *wmin_val = NULL;
    WordArray *one = NULL;
    WordArray *q_tmp = NULL;
    size_t wplen = 0;
    size_t bitplen = 0;
    bool is_goto_begin = false;
    int comp_p_q = 0;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(bits >= 256);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(wa_n != NULL);
    CHECK_PARAM(wa_d != NULL);

    bitplen = (bits + 1) >> 1;

    begin:

    DO(int_gen_prime(bitplen, prng, &wp));

    CHECK_NOT_NULL(one = wa_alloc_with_zero(wp->len));
    one->buf[0] = 1;

    CHECK_NOT_NULL(wmin_val = wa_alloc(wp->len));

    int_lshift(one, bitplen - 100, wmin_val);
    wa_change_len(wmin_val, wp->len);

    do {
        wa_free(wq);
        wq = NULL;

        DO(int_gen_prime(bits - bitplen, prng, &wq));
        ret = int_cmp(wq, wp);
        if (ret != 0) {
            if (ret > 0) {
                q_tmp = wq;
                wq = wp;
                wp = q_tmp;
            }
            CHECK_NOT_NULL(wsub_p_q = wa_alloc_with_zero(wp->len));
            wa_change_len(wq, wp->len);
            int_sub(wp, wq, wsub_p_q);

            // conformance with ANSI X9.31 requirement
            // |p-q| > 2^(prime bit length - 100)
            comp_p_q = int_cmp(wsub_p_q, wmin_val);
            wa_free(wsub_p_q);
            wsub_p_q = NULL;
        }
    } while (comp_p_q != 1);

    ret = RET_OK;

    wplen = wp->len;
    wa_change_len(wq, wplen);

    /* n = p * q */
    CHECK_NOT_NULL(wn = wa_alloc_with_zero(2 * wplen));
    int_mul(wq, wp, wn);

    /* fi = (p - 1) * (q - 1) */
    --wq->buf[0];
    --wp->buf[0];
    CHECK_NOT_NULL(fi = wa_alloc_with_zero(2 * wplen));
    int_mul(wq, wp, fi);
    ++wq->buf[0];
    ++wp->buf[0];

    CHECK_NOT_NULL(we = wa_alloc_from_ba(e));
    wa_change_len(we, 2 * wplen);

    wd = gfp_mod_inv_core(we, fi);
    if (wd == NULL) {
        is_goto_begin = true;
        goto cleanup;
    }

    if (int_bit_len(wn) != bits) {
        is_goto_begin = true;
        goto cleanup;
    }

    *wa_d = wd;
    *wa_n = wn;

    if (wa_p != NULL) {
        *wa_p = wp;
    }
    if (wa_q != NULL) {
        *wa_q = wq;
    }
    if (wa_fi != NULL) {
        *wa_fi = fi;
    }

    wd = NULL;
    wn = NULL;
    wp = NULL;
    wq = NULL;
    fi = NULL;

cleanup:

    wa_free(wn);
    wa_free(wd);
    wa_free(fi);
    wa_free(wq);
    wq = NULL;
    wa_free(wp);
    wa_free(we);
    wa_free(wsub_p_q);
    wa_free(one);
    wa_free(wmin_val);
    if (is_goto_begin) {
        is_goto_begin = false;
        goto begin;
    }

    return ret;
}

#define WA_TO_BA_WITH_TRUNC(wa, ba) {                   \
    CHECK_NOT_NULL(ba = wa_to_ba(wa));                  \
    DO(ba_change_len(ba, (int_bit_len(wa) + 7) >> 3));  \
}

int rsa_generate_privkey(RsaCtx *ctx, PrngCtx *prng, const size_t bits, const ByteArray *e, ByteArray **n,
                         ByteArray **d)
{
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(bits >= 256);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);

    DO(rsa_gen_privkey_core(ctx, prng, bits, e, NULL, NULL, NULL, &wn, &wd));

    WA_TO_BA_WITH_TRUNC(wd, *d);
    WA_TO_BA_WITH_TRUNC(wn, *n);

cleanup:

    wa_free(wn);
    wa_free(wd);

    return ret;
}

int rsa_generate_privkey_ext(RsaCtx *ctx, PrngCtx *prng, const size_t bits, const ByteArray *e, ByteArray **n,
                             ByteArray **d, ByteArray **p, ByteArray **q, ByteArray **dmp1, ByteArray **dmq1, ByteArray **iqmp)
{
    WordArray *fi = NULL;
    GfpCtx *gfp = NULL;
    GfpCtx *gfp1 = NULL;
    GfpCtx *gfq1 = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wdmq1 = NULL;
    WordArray *wdmp1 = NULL;
    WordArray *wiqmp = NULL;
    int ret = RET_OK;
    size_t wplen = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(bits != 0);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(dmp1 != NULL);
    CHECK_PARAM(dmq1 != NULL);
    CHECK_PARAM(iqmp != NULL);

    DO(rsa_gen_privkey_core(ctx, prng, bits, e, &wp, &wq, &fi, &wn, &wd));
    //https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.wskc.doc/wskc_c_rsagen.html

    wplen = wp->len;

    /* fi = (p - 1) * (q - 1) */
    --wq->buf[0];
    --wp->buf[0];

    /* e */
    CHECK_NOT_NULL(we = wa_alloc_from_ba(e));
    wa_change_len(we, 2 * wplen);

    /* exponent1 = d mod (p-1) */
    CHECK_NOT_NULL(wdmp1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfp1 = gfp_alloc(wp));
    gfp_mod(gfp1, wd, wdmp1);

    /* exponent2 = d mod (q-1) */
    CHECK_NOT_NULL(wdmq1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfq1 = gfp_alloc(wq));
    gfp_mod(gfq1, wd, wdmq1);

    ++wq->buf[0];
    ++wp->buf[0];

    /* coefficient = (inverse of q) mod p */
    CHECK_NOT_NULL(gfp = gfp_alloc(wp));
    CHECK_NOT_NULL(wiqmp = gfp_mod_inv_core(wq, wp));

    WA_TO_BA_WITH_TRUNC(wn, *n);
    WA_TO_BA_WITH_TRUNC(wp, *p);
    WA_TO_BA_WITH_TRUNC(wq, *q);
    WA_TO_BA_WITH_TRUNC(wd, *d);
    WA_TO_BA_WITH_TRUNC(wdmp1, *dmp1);
    WA_TO_BA_WITH_TRUNC(wdmq1, *dmq1);
    WA_TO_BA_WITH_TRUNC(wiqmp, *iqmp);

cleanup:

    wa_free(wn);
    wa_free(we);
    wa_free_private(wp);
    wa_free_private(wq);
    wa_free_private(wd);
    wa_free_private(wdmp1);
    wa_free_private(wdmq1);
    wa_free_private(wiqmp);
    wa_free_private(fi);
    gfp_free(gfp1);
    gfp_free(gfq1);
    gfp_free(gfp);

    return ret;

}

bool rsa_validate_key(RsaCtx *ctx, const ByteArray *n, const ByteArray *e, const ByteArray *d, const ByteArray *p,
                      const ByteArray *q, const ByteArray *dmp1, const ByteArray *dmq1, const ByteArray *iqmp)
{
    GfpCtx *gfp = NULL;
    GfpCtx *gfp1 = NULL;
    GfpCtx *gfq1 = NULL;
    WordArray *fi = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *we = NULL;
    WordArray *wn = NULL;
    WordArray *wd = NULL;
    WordArray *wdmq1 = NULL;
    WordArray *wdmp1 = NULL;
    WordArray *wiqmp = NULL;
    WordArray *wa_exp = NULL;
    int ret = RET_OK;
    size_t wplen = 0;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(dmp1 != NULL);
    CHECK_PARAM(dmq1 != NULL);
    CHECK_PARAM(iqmp != NULL);

    CHECK_NOT_NULL(wp = wa_alloc_from_ba(p));
    CHECK_NOT_NULL(wq = wa_alloc_from_ba(q));
    wplen = p->len;
    wa_change_len(wq, wp->len);
    CHECK_NOT_NULL(wn = wa_alloc_with_zero(2 * wplen));
    CHECK_NOT_NULL(fi = wa_alloc_with_zero(2 * wplen));

    /* n = p * q */
    int_mul(wq, wp, wn); //Модуль
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_ba(n));
    if (!int_equals(wa_exp, wn)) {
        SET_ERROR(RET_INVALID_RSA_N);
    }
    wa_free(wa_exp);
    wa_exp = NULL;
    /* fi = (p - 1) * (q - 1) */

    --wq->buf[0];
    --wp->buf[0];
    int_mul(wq, wp, fi);

    /* e */
    CHECK_NOT_NULL(we = wa_alloc_from_ba(e));
    wa_change_len(we, 2 * wplen);

    /* d = e^-1 mod fi*/
    CHECK_NOT_NULL(wd = gfp_mod_inv_core(we, fi));
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_ba(d));
    if (!int_equals(wa_exp, wd)) {
        SET_ERROR(RET_INVALID_RSA_D);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    /* exponent1 = d mod (p-1) */
    CHECK_NOT_NULL(wdmp1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfp1 = gfp_alloc(wp));
    gfp_mod(gfp1, wd, wdmp1);
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_ba(dmp1));
    if (!int_equals(wa_exp, wdmp1)) {
        SET_ERROR(RET_INVALID_RSA_DMP);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    /* exponent2 = d mod (q-1) */
    CHECK_NOT_NULL(wdmq1 = wa_alloc_with_zero(wplen));
    CHECK_NOT_NULL(gfq1 = gfp_alloc(wq));
    gfp_mod(gfq1, wd, wdmq1);
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_ba(dmq1));
    if (!int_equals(wa_exp, wdmq1)) {
        SET_ERROR(RET_INVALID_RSA_DMQ);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

    ++wq->buf[0];
    ++wp->buf[0];

    /* coefficient = (inverse of q) mod p */
    CHECK_NOT_NULL(gfp = gfp_alloc(wp));
    CHECK_NOT_NULL(wiqmp = gfp_mod_inv_core(wq, wp));
    CHECK_NOT_NULL(wa_exp = wa_alloc_from_ba(iqmp));
    if (!int_equals(wa_exp, wiqmp)) {
        SET_ERROR(RET_INVALID_RSA_IQMP);
    }
    wa_free(wa_exp);
    wa_exp = NULL;

cleanup:

    wa_free(wn);
    wa_free(we);
    wa_free_private(wp);
    wa_free_private(wq);
    wa_free_private(wd);
    wa_free_private(wdmp1);
    wa_free_private(wdmq1);
    wa_free_private(wiqmp);
    wa_free_private(fi);
    gfp_free(gfp1);
    gfp_free(gfq1);
    gfp_free(gfp);

    return ret == RET_OK ? true : false;
}

int rsa_init_encrypt_pkcs1_v1_5(RsaCtx *ctx, PrngCtx *prng, const ByteArray *n, const ByteArray *e)
{
    int ret = RET_OK;
    WordArray *wn = NULL;
    ByteArray *seed = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(prng != NULL);

    wa_free_private(ctx->d);
    ctx->d = NULL;

    wa_free(ctx->e);
    CHECK_NOT_NULL(ctx->e = wa_alloc_from_ba(e));

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));
    wa_change_len(ctx->e, ctx->gfp->p->len);

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    DO(prng_next_bytes(prng, seed));
    prng_free(ctx->prng);
    CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    ctx->mode_id = RSA_MODE_ENCRYPT_PKCS;

cleanup:

    wa_free(wn);
    ba_free_private(seed);

    return ret;
}

int rsa_init_decrypt_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *n, const ByteArray *d)
{
    int ret = RET_OK;
    WordArray *wn = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);

    wa_free_private(ctx->d);
    CHECK_NOT_NULL(ctx->d = wa_alloc_from_ba(d));

    wa_free(ctx->e);
    ctx->e = NULL;

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));

    wa_change_len(ctx->d, ctx->gfp->p->len);

    ctx->mode_id = RSA_MODE_DECRYPT_PKCS;

cleanup:

    wa_free(wn);

    return ret;
}

int rsa_init_sign_pkcs1_v1_5(RsaCtx *ctx, RsaHashType hash_type, const ByteArray *n, const ByteArray *d)
{
    WordArray *wn = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);

    wa_free_private(ctx->d);
    CHECK_NOT_NULL(ctx->d = wa_alloc_from_ba(d));

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));

    ctx->hash_type = hash_type;

    wa_change_len(ctx->d, ctx->gfp->p->len);

    ctx->mode_id = RSA_MODE_SIGN_PKCS;

cleanup:

    wa_free(wn);

    return ret;
}

int rsa_init_verify_pkcs1_v1_5(RsaCtx *ctx, RsaHashType hash_type, const ByteArray *n, const ByteArray *e)
{
    WordArray *wn = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(e != NULL);

    wa_free_private(ctx->d);
    ctx->d = NULL;

    wa_free(ctx->e);
    CHECK_NOT_NULL(ctx->e = wa_alloc_from_ba(e));

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));

    wa_change_len(ctx->e, ctx->gfp->p->len);
    ctx->hash_type = hash_type;

    ctx->mode_id = RSA_MODE_VERIFY_PKCS;

cleanup:

    wa_free(wn);

    return ret;
}

int rsa_init_encrypt_oaep(RsaCtx *ctx, PrngCtx *prng, RsaHashType htype, ByteArray *label, const ByteArray *n,
                          const ByteArray *e)
{
    int ret = RET_OK;
    WordArray *wn = NULL;
    ByteArray *seed = NULL;
    size_t len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(e != NULL);
    CHECK_PARAM(prng != NULL);

    wa_free_private(ctx->d);
    ctx->d = NULL;
    ctx->hash_type = htype;

    wa_free(ctx->e);
    CHECK_NOT_NULL(ctx->e = wa_alloc_from_ba(e));

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));
    wa_change_len(ctx->e, ctx->gfp->p->len);

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    if (len < (size_t)(2 * HASH_LEN[htype] + 2)) {
        SET_ERROR(RET_INVALID_PARAM);
    }

    CHECK_NOT_NULL(seed = ba_alloc_by_len(128));
    DO(prng_next_bytes(prng, seed));
    prng_free(ctx->prng);
    CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

    ctx->label = label;
    ctx->mode_id = RSA_MODE_ENCRYPT_OAEP;

cleanup:

    wa_free(wn);
    ba_free_private(seed);

    return ret;
}

int rsa_init_decrypt_oaep(RsaCtx *ctx, RsaHashType htype, ByteArray *label, const ByteArray *n, const ByteArray *d)
{
    int ret = RET_OK;
    WordArray *wn = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(d != NULL);

    wa_free_private(ctx->d);
    CHECK_NOT_NULL(ctx->d = wa_alloc_from_ba(d));

    wa_free(ctx->e);
    ctx->e = NULL;
    ctx->hash_type = htype;

    gfp_free(ctx->gfp);
    CHECK_NOT_NULL(wn = wa_alloc_from_ba(n));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(wn));

    wa_change_len(ctx->d, ctx->gfp->p->len);

    ctx->mode_id = RSA_MODE_DECRYPT_OAEP;
    ctx->label = label;

cleanup:

    wa_free(wn);

    return ret;
}

int rsa_encrypt(RsaCtx *ctx, const ByteArray *data, ByteArray **encrypted_data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
        case RSA_MODE_ENCRYPT_OAEP:
            DO(rsa_encrypt_oaep(ctx, data, ctx->label, encrypted_data));
            break;
        case RSA_MODE_ENCRYPT_PKCS:
            DO(rsa_encrypt_pkcs1_v1_5(ctx, data, encrypted_data));
            break;
        default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int rsa_decrypt(RsaCtx *ctx, const ByteArray *encrypted_data, ByteArray **data)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(encrypted_data != NULL);

    switch (ctx->mode_id) {
        case RSA_MODE_DECRYPT_OAEP:
            DO(rsa_decrypt_oaep(ctx, encrypted_data, data));
            break;
        case RSA_MODE_DECRYPT_PKCS:
            DO(rsa_decrypt_pkcs1_v1_5(ctx, encrypted_data, data));
            break;
        default:
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

int rsa_sign_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *hash, ByteArray **sign)
{
    WordArray *em_wa = NULL;
    WordArray *sign_wa = NULL;
    size_t len;
    uint8_t *em = NULL;
    uint8_t tlen;
    uint8_t hlen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    tlen = HASH_AID_LEN[ctx->hash_type];
    hlen = HASH_LEN[ctx->hash_type];
    if (hash->len != hlen) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    CHECK_PARAM((size_t)(tlen + hlen + 11) <= len);
    CHECK_NOT_NULL(em = malloc(len));
    /*
     * EMSA-PKCS1-v1_5-ENCODE
     * EM = 0x00 || 0x01 || PS || 0x00 || AlgorithmIdentifier || HASH.
     */
    em[0] = 0;
    em[1] = 1;
    memset(em + 2, 0xff, len - tlen - hlen - 3);
    em[len - hlen - tlen - 1] = 0;
    memcpy(em + len - hlen - tlen, pkcs15_get_aid(ctx->hash_type), tlen);
    DO(ba_to_uint8(hash, em + len - hlen, hlen));

    CHECK_NOT_NULL(em_wa = wa_alloc_from_be(em, len));
    DO(rsaedp(ctx->gfp, ctx->d, em_wa, &sign_wa));

    CHECK_NOT_NULL(*sign = wa_to_ba(sign_wa));

cleanup:

    wa_free(em_wa);
    wa_free(sign_wa);
    free(em);

    return ret;
}

int rsa_verify_pkcs1_v1_5(RsaCtx *ctx, const ByteArray *hash, const ByteArray *sign)
{
    size_t len;
    uint8_t *em = NULL;
    uint8_t tlen;
    uint8_t hlen;
    WordArray *em_wa = NULL;
    WordArray *sign_wa = NULL;
    int ret = RET_OK;
    size_t i;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    if (ctx->mode_id != RSA_MODE_VERIFY_PKCS) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = ctx->gfp->p->len * WORD_BYTE_LENGTH;
    CHECK_NOT_NULL(em = malloc(len));
    tlen = HASH_AID_LEN[ctx->hash_type];
    hlen = HASH_LEN[ctx->hash_type];
    if (hash->len != hlen) {
        SET_ERROR(RET_INVALID_HASH_LEN);
    }

    CHECK_NOT_NULL(sign_wa = wa_alloc_from_ba(sign));
    DO(rsaedp(ctx->gfp, ctx->e, sign_wa, &em_wa));

    DO(wa_to_uint8(em_wa, em, len));
    DO(uint8_swap(em, len, em, len));

    if (em[0] != 0 || em[1] != 1 || em[len - hlen - tlen - 1] != 0) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    for (i = len - tlen - hlen - 2; i >= 2; i--) {
        if (em[i] != 0xff) {
            SET_ERROR(RET_VERIFY_FAILED);
        }
    }

    if (memcmp(em + len - tlen - hlen, pkcs15_get_aid(ctx->hash_type), tlen)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    if (memcmp(em + len - hlen, ba_get_buf(hash), hlen)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    free(em);
    wa_free(em_wa);
    wa_free(sign_wa);

    return ret;
}

void rsa_free(RsaCtx *ctx)
{
    if (ctx) {
        wa_free_private(ctx->e);
        wa_free_private(ctx->d);
        prng_free(ctx->prng);
        gfp_free(ctx->gfp);
    }
    free(ctx);
}
