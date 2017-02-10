/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ecdsa.h"
#include "ecdsa_internal.h"
#include "ecdsa_params_internal.h"
#include "crypto_cache_internal.h"
#include "math_int_internal.h"
#include "macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/ecdsa.c"

#define ECDSA_DEFAULT_WIN_WIDTH 5

static void ecdsa_params_free(EcdsaParamsCtx *params)
{
    if (params != NULL) {
        ecp_free(params->ecp);
        gfp_free(params->gfq);
        ec_point_free(params->p);
        ec_precomp_free(params->precomp_p);
        free(params);
    }
}

static EcdsaParamsCtx *ecdsa_params_alloc(const ByteArray *p, const ByteArray *a, const ByteArray *b,
        const ByteArray *q, const ByteArray *px, const ByteArray *py)
{
    WordArray *wa = NULL;
    WordArray *wb = NULL;
    WordArray *wp = NULL;
    WordArray *wq = NULL;
    WordArray *wpx = NULL;
    WordArray *wpy = NULL;
    size_t len;
    int ret = RET_OK;
    EcdsaParamsCtx *params = NULL;

    CALLOC_CHECKED(params, sizeof(EcdsaParamsCtx));

    CHECK_NOT_NULL(wp = wa_alloc_from_ba(p));
    len = WA_LEN_FROM_BITS(int_bit_len(wp));
    wa_change_len(wp, len);

    CHECK_NOT_NULL(wa = wa_alloc_from_ba(a));
    wa_change_len(wa, len);

    CHECK_NOT_NULL(wb = wa_alloc_from_ba(b));
    wa_change_len(wb, len);

    CHECK_NOT_NULL(params->ecp = ecp_alloc(wp, wa, wb));

    CHECK_NOT_NULL(wq = wa_alloc_from_ba(q));
    wa_change_len(wq, len);

    CHECK_NOT_NULL(params->gfq = gfp_alloc(wq));

    CHECK_NOT_NULL(wpx = wa_alloc_from_ba(px));
    wa_change_len(wpx, len);

    CHECK_NOT_NULL(wpy = wa_alloc_from_ba(py));
    wa_change_len(wpy, len);

    CHECK_NOT_NULL(params->p = ec_point_aff_alloc(wpx, wpy));

    params->len = len;

cleanup:

    if (ret != RET_OK) {
        ecdsa_params_free(params);
        params = NULL;
    }

    wa_free(wa);
    wa_free(wb);
    wa_free(wp);
    wa_free(wq);
    wa_free(wpx);
    wa_free(wpy);

    return params;
}

static int public_key_to_ec_point(const EcdsaParamsCtx *params, const ByteArray *qx, const ByteArray *qy, ECPoint **q)
{
    WordArray *wqx = NULL;
    WordArray *wqy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    CHECK_NOT_NULL(wqx = wa_alloc_from_ba(qx));
    CHECK_NOT_NULL(wqy = wa_alloc_from_ba(qy));

    /* Проверка корректности открытого ключа 0 <= qx < p, 0 < qy < p */
    if (int_cmp(wqx, params->ecp->gfp->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_cmp(wqy, params->ecp->gfp->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_is_zero(wqy)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    wa_change_len(wqx, params->len);
    wa_change_len(wqy, params->len);

    /* Открытый ключ принадлежит эллиптической кривой. */
    if (!ecp_is_on_curve(params->ecp, wqx, wqy)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    CHECK_NOT_NULL(*q = ec_point_aff_alloc(wqx, wqy));

cleanup:

    wa_free(wqx);
    wa_free(wqy);

    return ret;
}

EcdsaCtx *ecdsa_alloc(EcdsaParamsId params_id)
{
    const EcdsaDefaultParamsCtx *def_params;
    ByteArray *a = NULL;
    ByteArray *b = NULL;
    ByteArray *p = NULL;
    ByteArray *q = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    EcdsaCtx *ctx = NULL;
    int ret = RET_OK;

    CHECK_NOT_NULL(def_params = ecdsa_get_defaut_params(params_id));
    CHECK_NOT_NULL(a = ba_alloc_from_uint8(def_params->a, def_params->len));
    CHECK_NOT_NULL(b = ba_alloc_from_uint8(def_params->b, def_params->len));
    CHECK_NOT_NULL(p = ba_alloc_from_uint8(def_params->p, def_params->len));
    CHECK_NOT_NULL(q = ba_alloc_from_uint8(def_params->q, def_params->len));
    CHECK_NOT_NULL(px = ba_alloc_from_uint8(def_params->px, def_params->len));
    CHECK_NOT_NULL(py = ba_alloc_from_uint8(def_params->py, def_params->len));
    CHECK_NOT_NULL(ctx = ecdsa_alloc_ext(p, a, b, q, px, py));

cleanup:

    ba_free(a);
    ba_free(b);
    ba_free(p);
    ba_free(q);
    ba_free(px);
    ba_free(py);
    if (ret != RET_OK) {
        ecdsa_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

EcdsaCtx *ecdsa_alloc_ext_new(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py)
{
    EcdsaCtx *ctx = NULL;
    int ret = RET_OK;

    CHECK_PARAM(p != NULL);
    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(px != NULL);
    CHECK_PARAM(py != NULL);

    CALLOC_CHECKED(ctx, sizeof(EcdsaCtx));
    CHECK_NOT_NULL(ctx->params = ecdsa_params_alloc(p, a, b, q, px, py));

    ctx->prng = NULL;
    ctx->priv_key = NULL;
    ctx->pub_key = NULL;
    ctx->sign_status = false;
    ctx->verify_status = false;

cleanup:

    if (ret != RET_OK) {
        ecdsa_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

EcdsaCtx *ecdsa_alloc_ext(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py)
{
    EcdsaCtx *ctx;

    ctx = crypto_cache_get_ecdsa(p, a, b, q, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return ecdsa_alloc_ext_new(p, a, b, q, px, py);

}

int ecdsa_get_params(EcdsaCtx *ctx, ByteArray **p, ByteArray **a, ByteArray **b, ByteArray **q,
        ByteArray **px, ByteArray **py)
{
    size_t blen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(p != NULL);
    CHECK_PARAM(a != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(px != NULL);
    CHECK_PARAM(py != NULL);

    blen = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;

    CHECK_NOT_NULL(*p = wa_to_ba(ctx->params->ecp->gfp->p));
    DO(ba_change_len(*p, blen));

    CHECK_NOT_NULL(*a = wa_to_ba(ctx->params->ecp->a));
    DO(ba_change_len(*a, blen));

    CHECK_NOT_NULL(*b = wa_to_ba(ctx->params->ecp->b));
    DO(ba_change_len(*b, blen));

    CHECK_NOT_NULL(*q = wa_to_ba(ctx->params->gfq->p));
    DO(ba_change_len(*q, blen));

    CHECK_NOT_NULL(*px = wa_to_ba(ctx->params->p->x));
    DO(ba_change_len(*px, blen));

    CHECK_NOT_NULL(*py = wa_to_ba(ctx->params->p->y));
    DO(ba_change_len(*py, blen));

cleanup:

    return ret;
}

int ecdsa_equals_params(const EcdsaCtx *param_a, const EcdsaCtx *param_b, bool *equals)
{
    int ret = RET_OK;

    CHECK_PARAM(param_a != NULL);
    CHECK_PARAM(param_b != NULL);
    CHECK_PARAM(equals != NULL);

    if ((param_a->params->len != param_b->params->len)) {
        *equals = false;
        return RET_OK;
    }

    if (param_a->params->ecp->a_equal_minus_3 != param_b->params->ecp->a_equal_minus_3) {
        *equals = false;
        return RET_OK;
    }

    if (param_a->params->ecp->len != param_b->params->ecp->len) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->ecp->a, param_b->params->ecp->a)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->ecp->b, param_b->params->ecp->b)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->ecp->gfp->p, param_b->params->ecp->gfp->p)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->gfq->p, param_b->params->gfq->p)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->p->x, param_b->params->p->x)
            || wa_cmp(param_a->params->p->y, param_b->params->p->y)
            || wa_cmp(param_a->params->p->z, param_b->params->p->z)) {
        *equals = false;
        return RET_OK;
    }

    *equals = true;

cleanup:

    return ret;
}

static int ecdsa_set_verify_precomp(EcdsaCtx *ctx, int verify_comb_opt_level, int verify_win_opt_level)
{
    EcdsaParamsCtx *params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (verify_comb_opt_level == 0 && verify_win_opt_level == 0) {
        if (default_opt_level != 0) {
            verify_comb_opt_level = (default_opt_level >> 4) & 0x0f;
            verify_win_opt_level = default_opt_level & 0x0f;
        } else {
            verify_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }
    }

    if (verify_comb_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_COMB
                || ctx->precomp_q->ctx.comb->comb_width != verify_comb_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ecp_calc_comb_precomp(params->ecp, ctx->pub_key, verify_comb_opt_level, &ctx->precomp_q));
        }
    } else if (verify_win_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_WIN
                || ctx->precomp_q->ctx.win->win_width != verify_win_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ecp_calc_win_precomp(params->ecp, ctx->pub_key, verify_win_opt_level, &ctx->precomp_q));
        }
    }

cleanup:

    return ret;
}

EcdsaCtx *ecdsa_copy_params_with_alloc(const EcdsaCtx *param)
{
    int ret = RET_OK;

    EcdsaCtx *param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CALLOC_CHECKED(param_copy, sizeof(EcdsaCtx));
    CALLOC_CHECKED(param_copy->params, sizeof(EcdsaParamsCtx));

    CHECK_NOT_NULL(param_copy->params->ecp = ecp_copy_with_alloc(param->params->ecp));
    CHECK_NOT_NULL(param_copy->params->gfq = gfp_copy_with_alloc(param->params->gfq));
    param_copy->params->len = param->params->len;
    CHECK_NOT_NULL(param_copy->params->p = ec_point_copy_with_alloc(param->params->p));
    if (param->params->precomp_p) {
        CHECK_NOT_NULL(param_copy->params->precomp_p = ec_copy_precomp_with_alloc(param->params->precomp_p));
    }

    if (param->precomp_q != NULL) {
        int verify_comb_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? param->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? param->precomp_q->ctx.win->win_width : 0;
        ecdsa_set_verify_precomp(param_copy, verify_comb_opt_level, verify_win_opt_level);
    }

    return param_copy;

cleanup:

    ecdsa_free(param_copy);

    return NULL;
}

EcdsaCtx *ecdsa_copy_with_alloc(const EcdsaCtx *param)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;

    EcdsaCtx *param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CHECK_NOT_NULL(param_copy = ecdsa_copy_params_with_alloc(param));

    if (param->prng) {
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(prng_next_bytes(param->prng, seed));
        CHECK_NOT_NULL(param_copy->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    }

    if (param->priv_key) {
        CHECK_NOT_NULL(param_copy->priv_key = wa_copy_with_alloc(param->priv_key));
    }

    if (param->pub_key) {
        CHECK_NOT_NULL(param_copy->pub_key = ec_point_copy_with_alloc(param->pub_key));
    }

    if (param->precomp_q) {
        if (param_copy->precomp_q) {
            ec_precomp_free(param_copy->precomp_q);
        }

        CHECK_NOT_NULL(param_copy->precomp_q = ec_copy_precomp_with_alloc(param->precomp_q));
    }

    param_copy->sign_status = param->sign_status;
    param_copy->verify_status = param->verify_status;

    ba_free_private(seed);

    return param_copy;

cleanup:

    ecdsa_free(param_copy);
    ba_free_private(seed);

    return NULL;
}

int ecdsa_generate_privkey(EcdsaCtx *ctx, PrngCtx *prng, ByteArray **d)
{
    WordArray *wd = NULL;
    size_t blen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(d != NULL);

    CHECK_NOT_NULL(wd = wa_alloc(ctx->params->len));

    DO(int_rand(prng, ctx->params->gfq->p, wd));
    *d = wa_to_ba(wd);
    blen = (int_bit_len(ctx->params->gfq->p) + 7) / 8;
    DO(ba_change_len(*d, blen));

cleanup:

    wa_free_private(wd);

    return ret;
}

static int ecdsa_set_sign_precomp(const EcdsaCtx *ctx, int sign_comb_opt_level, int sign_win_opt_level)
{
    EcdsaParamsCtx *params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (sign_comb_opt_level == 0 && sign_win_opt_level == 0) {
        if (default_opt_level != 0) {
            sign_comb_opt_level = (default_opt_level >> 12) & 0x0f;
            sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        } else {
            sign_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }
    }

    if (sign_comb_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_COMB
                || params->precomp_p->ctx.comb->comb_width != sign_comb_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            DO(ecp_calc_comb_precomp(params->ecp, params->p, sign_comb_opt_level, &params->precomp_p));
        }
    } else if (sign_win_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_WIN
                || params->precomp_p->ctx.win->win_width != sign_win_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            DO(ecp_calc_win_precomp(params->ecp, params->p, sign_win_opt_level, &params->precomp_p));
        }
    }

cleanup:

    return ret;
}

int ecdsa_get_pubkey(EcdsaCtx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy)
{
    size_t blen;
    WordArray *wd = NULL;
    ECPoint *r = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    CHECK_NOT_NULL(wd = wa_alloc_from_ba(d));
    if (int_is_zero(wd) || int_cmp(wd, ctx->params->gfq->p) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }
    wa_change_len(wd, ctx->params->len);

    CHECK_NOT_NULL(r = ec_point_alloc(ctx->params->ecp->len));
    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }
        DO(ecdsa_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, wd, NULL, NULL, r));

    blen = (int_bit_len(ctx->params->ecp->gfp->p) + 7) / 8;
    CHECK_NOT_NULL(*qx = wa_to_ba(r->x));
    CHECK_NOT_NULL(*qy = wa_to_ba(r->y));
    DO(ba_change_len(*qx, blen));
    DO(ba_change_len(*qy, blen));

cleanup:

    ec_point_free(r);
    wa_free_private(wd);

    return ret;
}

int ecdsa_compress_pubkey(EcdsaCtx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q, int *last_qy_bit)
{
    ECPoint *ec_point = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(last_qy_bit != NULL);

    DO(public_key_to_ec_point(ctx->params, qx, qy, &ec_point));

    CHECK_NOT_NULL(*q = ba_alloc_from_uint8(qx->buf, qx->len));
    *last_qy_bit = int_get_bit(ec_point->y, 0);

cleanup:

    ec_point_free(ec_point);

    return ret;
}

int ecdsa_decompress_pubkey(EcdsaCtx *ctx, const ByteArray *q, int last_qy_bit, ByteArray **qx, ByteArray **qy)
{
    WordArray *x = NULL;
    WordArray *y = NULL;
    GfpCtx *gfp;
    size_t blen;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    if (last_qy_bit != 0 && last_qy_bit != 1) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    CHECK_NOT_NULL(x = wa_alloc_from_ba(q));
    wa_change_len(x, ctx->params->len);

    CHECK_NOT_NULL(y = wa_alloc(ctx->params->len));

    gfp = ctx->params->ecp->gfp;
    if (int_cmp(x, gfp->p) >= 0 || int_is_zero(x)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    /* Восстановление точки эллиптической кривой. */
    wa_free(y);
    y = NULL;

    CHECK_NOT_NULL(y = wa_alloc(ctx->params->len));
    gfp_mod_sqr(gfp, x, y);
    gfp_mod_add(gfp, y, ctx->params->ecp->a, y);
    gfp_mod_mul(gfp, x, y, y);
    gfp_mod_add(gfp, y, ctx->params->ecp->b, y);
    if (!gfp_mod_sqrt(gfp, y, y)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    /* Если младший бит y не равен last_qy_bit y = p - y. */
    if (int_get_bit(y, 0) != last_qy_bit) {
        gfp_mod_sub(gfp, gfp->p, y, y);
    }

    blen = (int_bit_len(gfp->p) + 7) / 8;
    *qx = wa_to_ba(x);
    *qy = wa_to_ba(y);
    DO(ba_change_len(*qx, blen));
    DO(ba_change_len(*qy, blen));

    ret = RET_OK;

cleanup:

    wa_free(x);
    wa_free(y);

    return ret;
}

int ecdsa_set_opt_level(EcdsaCtx *ctx, OptLevelId opt_level)
{
    int ret = RET_OK;
    int sign_comb_opt_level;
    int sign_win_opt_level;
    int verify_comb_opt_level;
    int verify_win_opt_level;

    CHECK_PARAM(ctx != NULL);

    if (ctx->params == NULL) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    sign_comb_opt_level = (opt_level >> 12) & 0x0f;
    sign_win_opt_level = (opt_level >> 8) & 0x0f;
    verify_comb_opt_level = (opt_level >> 4) & 0x0f;
    verify_win_opt_level = opt_level & 0x0f;

    CHECK_PARAM(sign_comb_opt_level == 0 || sign_win_opt_level == 0);
    CHECK_PARAM(sign_win_opt_level == 0 || (sign_win_opt_level & 1) == 1);
    CHECK_PARAM(verify_comb_opt_level == 0 || verify_win_opt_level == 0);
    CHECK_PARAM(verify_win_opt_level == 0 || (verify_win_opt_level & 1) == 1);

    DO(ecdsa_set_sign_precomp(ctx, sign_comb_opt_level, sign_win_opt_level));
    DO(ecdsa_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));

cleanup:

    return ret;
}

int ecdsa_init_sign(EcdsaCtx *ctx, const ByteArray *d, PrngCtx *prng)
{
    ByteArray *seed = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(prng != NULL);

    if (ctx->params == NULL) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    wa_free_private(ctx->priv_key);
    CHECK_NOT_NULL(ctx->priv_key = wa_alloc_from_ba(d));
    ec_point_free(ctx->pub_key);
    ctx->pub_key = NULL;

    if (ctx->precomp_q != NULL) {
        int verify_comb_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_q->ctx.win->win_width : 0;

        ec_precomp_free(ctx->precomp_q);
        ctx->precomp_q = NULL;
        ecdsa_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level);
    }

    /* Проверка корректности закрытого ключа. */
    if (int_is_zero(ctx->priv_key) || (int_cmp(ctx->priv_key, ctx->params->gfq->p) >= 0)) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(ctx->priv_key, ctx->params->len);

    CHECK_NOT_NULL(seed = ba_alloc_by_len(128));

    /* Установка датчика псевдослучайных чисел. */
    DO(prng_next_bytes(prng, seed));

    if (ctx->prng != NULL) {
        DO(prng_seed(ctx->prng, seed));
    } else {
        CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    }

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }

        ecdsa_set_sign_precomp(ctx, 0, sign_win_opt_level);
    }

    ctx->sign_status = true;

cleanup:

    ba_free(seed);

    return ret;
}


int ecdsa_sign(EcdsaCtx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s)
{
    WordArray *e = NULL;
    WordArray *k = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *t = NULL;
    ByteArray *br = NULL;
    ByteArray *bs = NULL;
    ECPoint *c = NULL;
    size_t len;
    const EcdsaParamsCtx *params;
    const WordArray *q;
    int ret = RET_OK;
    size_t ln;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(r != NULL);

    params = ctx->params;

    if (!ctx->sign_status) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = params->len;
    q = params->gfq->p;

    CHECK_NOT_NULL(e = wa_alloc_from_be(hash->buf, hash->len));
    wa_change_len(e, len);
    int_truncate(e, int_bit_len(q));

    CHECK_NOT_NULL(k = wa_alloc(len));
    CHECK_NOT_NULL(wr = wa_alloc(len));
    CHECK_NOT_NULL(ws = wa_alloc(len));
    CHECK_NOT_NULL(c = ec_point_alloc(params->len));
    do {
        do {
            /* Шаг 2. Сгенерировать случайное число k (0 < k < q).  */
            DO(int_rand(ctx->prng, q, k));

            /* Шаг 3. Вычислить точку эллиптической кривой C = kP,
             * c = (cx, cy) и определить r = cx (mod q). */
            DO(ecp_dual_mul_opt(params->ecp, params->precomp_p, k, NULL, NULL, c));

            CHECK_NOT_NULL(t = wa_copy_with_alloc(c->x));
            wa_change_len(t, 2 * len);
            int_div(t, q, NULL, wr);
            wa_free(t);
            t = NULL;

            /* Если r = 0, то вернуться к Шагу 2.  */
        } while (int_is_zero(wr));

        /* t = k^(-1);
         * s = t * (rd + e)(mod q). */
        t = gfp_mod_inv(params->gfq, k);
        gfp_mod_mul(params->gfq, wr, ctx->priv_key, ws);
        gfp_mod_add(params->gfq, ws, e, ws);
        gfp_mod_mul(params->gfq, ws, t, ws);
        wa_free_private(t);
        t = NULL;

    } while (int_is_zero(ws));

    ln = (int_bit_len(q) + 7) >> 3;

    CHECK_NOT_NULL(br = wa_to_ba(wr));
    CHECK_NOT_NULL(bs = wa_to_ba(ws));

    DO(ba_change_len(br, ln));
    DO(ba_change_len(bs, ln));

    *r = br;
    *s = bs;

    br = NULL;
    bs = NULL;

cleanup:

    wa_free(e);
    wa_free_private(k);
    wa_free(wr);
    wa_free(ws);
    ba_free(br);
    ba_free(bs);
    ec_point_free(c);

    return ret;
}

int ecdsa_init_verify(EcdsaCtx *ctx, const ByteArray *qx, const ByteArray *qy)
{
    int verify_comb_opt_level;
    int verify_win_opt_level;
    int ret = RET_OK;
    ECPoint *pub_key = NULL;
    bool need_update_precomp_q = false;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    wa_free_private(ctx->priv_key);
    ctx->priv_key = NULL;

    if (ctx->prng != NULL) {
        prng_free(ctx->prng);
        ctx->prng = NULL;
    }

    /* Установка открытого ключа. */
    DO(public_key_to_ec_point(ctx->params, qx, qy, &pub_key));
    if (ctx->pub_key != NULL) {
        if (wa_cmp(pub_key->x, ctx->pub_key->x) != 0 || wa_cmp(pub_key->y, ctx->pub_key->y) != 0
                || wa_cmp(pub_key->z, ctx->pub_key->z) != 0) {
            ec_point_free(ctx->pub_key);
            ctx->pub_key = pub_key;
            pub_key = NULL;
            need_update_precomp_q = true;
        }
    } else {
        ctx->pub_key = pub_key;
        pub_key = NULL;
        need_update_precomp_q = true;
    }

    if (ctx->precomp_q != NULL) {
        if (need_update_precomp_q) {
            verify_comb_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_q->ctx.comb->comb_width : 0;
            verify_win_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_q->ctx.win->win_width : 0;

            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
        }
    } else {
        verify_comb_opt_level = 0;
        verify_win_opt_level = default_opt_level & 0x0f;
        if (verify_win_opt_level == 0) {
            verify_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }
        need_update_precomp_q = true;
    }

    if (need_update_precomp_q) {
        DO(ecdsa_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));
    }

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = ECDSA_DEFAULT_WIN_WIDTH;
        }

        DO(ecdsa_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    ctx->verify_status = true;

cleanup:

    ec_point_free(pub_key);

    return ret;
}

int ecdsa_verify(EcdsaCtx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s)
{
    WordArray *e = NULL;
    WordArray *z1 = NULL;
    WordArray *z2 = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *s_inv = NULL;
    WordArray *r_act = NULL;
    WordArray *t = NULL;
    ECPoint *c = NULL;
    const EcdsaParamsCtx *params;
    const WordArray *q;
    int ret = RET_OK;
    size_t len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    params = ctx->params;

    if (ctx->verify_status == 0) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    len = params->len;
    q = params->gfq->p;

    /* Проверка ЭЦП. */
    CHECK_NOT_NULL(wr = wa_alloc_from_ba(r));
    CHECK_NOT_NULL(ws = wa_alloc_from_ba(s));

    wa_change_len(wr, len);
    wa_change_len(ws, len);

    /* 0 < r < n і 0 < s < n, иначе подпись неверная. */
    if ((int_cmp(wr, ctx->params->gfq->p) >= 0) || (int_cmp(ws, ctx->params->gfq->p) >= 0)
            || int_is_zero(wr) || int_is_zero(ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(e = wa_alloc_from_be(hash->buf, hash->len));
    wa_change_len(e, ctx->params->len);
    int_truncate(e, int_bit_len(q));

    if (int_is_zero(e)) {
        e->buf[0] = 1;
    }

    /* Шаг 3. Вычислить значение s = s^(-1)(mod q). */
    s_inv = gfp_mod_inv(ctx->params->gfq, ws);

    /* Шаг 4. Вычислить значения z1 = s*e(mod q), z2 = s*r(mod q). */
    CHECK_NOT_NULL(z1 = wa_alloc(params->len));
    CHECK_NOT_NULL(z2 = wa_alloc(params->len));
    gfp_mod_mul(ctx->params->gfq, s_inv, e, z1);
    gfp_mod_mul(ctx->params->gfq, s_inv, wr, z2);

    /* Шаг 5. Вычислить точку эллиптической кривой C = z1*P+z2*Q */
    CHECK_NOT_NULL(c = ec_point_alloc(params->len));
    DO(ecp_dual_mul_opt(ctx->params->ecp, ctx->params->precomp_p, z1, ctx->precomp_q, z2, c));

    CHECK_NOT_NULL(t = wa_copy_with_alloc(c->x));
    wa_change_len(t, 2 * len);

    CHECK_NOT_NULL(r_act = wa_alloc(params->len));
    int_div(t, q, NULL, r_act);

    if (!int_equals(r_act, wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(e);
    wa_free(z1);
    wa_free(z2);
    wa_free(wr);
    wa_free(ws);
    wa_free(s_inv);
    wa_free(r_act);
    wa_free(t);
    ec_point_free(c);

    return ret;
}

void ecdsa_free(EcdsaCtx *ctx)
{
    if (ctx) {
        wa_free_private(ctx->priv_key);
        ecdsa_params_free(ctx->params);
        prng_free(ctx->prng);
        ec_point_free(ctx->pub_key);
        ec_precomp_free(ctx->precomp_q);
        free(ctx);
    }
}
