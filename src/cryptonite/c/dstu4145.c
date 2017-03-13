/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <string.h>

#include "dstu4145.h"
#include "dstu4145_params_internal.h"
#include "crypto_cache_internal.h"
#include "math_int_internal.h"
#include "macros_internal.h"

#define DSTU4145_DEFAULT_WIN_WIDTH 5

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/dstu4145.c"

static int public_key_to_ec_point(Dstu4145ParamsCtx *params, const ByteArray *qx, const ByteArray *qy, ECPoint **q)
{
    int ret = RET_OK;
    WordArray *x = NULL;
    WordArray *y = NULL;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    CHECK_NOT_NULL(x = wa_alloc_from_ba(qx));
    CHECK_NOT_NULL(y = wa_alloc_from_ba(qy));

    wa_change_len(x, params->ec2m->len);
    wa_change_len(y, params->ec2m->len);

    /* Координаты точки принадлежат основному полю. */
    if (int_bit_len(x) > params->m) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_bit_len(y) > params->m) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (params->is_onb) {
        DO(onb_to_pb(params, x));
        DO(onb_to_pb(params, y));
    }

    if (!ec2m_is_on_curve(params->ec2m, x, y)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    CHECK_NOT_NULL(*q = ec_point_aff_alloc(x, y));

cleanup:

    wa_free(x);
    wa_free(y);

    return ret;
}

Dstu4145Ctx *dstu4145_alloc_new(Dstu4145ParamsId params_id)
{
    const Dstu4145DefaultParamsCtx *def_params;
    ByteArray *b = NULL;
    ByteArray *n = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    Dstu4145Ctx *ctx = NULL;
    int ret = RET_OK;

    def_params = dstu4145_get_defaut_params(params_id);
    if (def_params == NULL) {
        ERROR_CREATE(RET_INVALID_PARAM);
        return NULL;
    }

    CHECK_NOT_NULL(b = ba_alloc_from_uint8(def_params->b, sizeof(def_params->b)));
    CHECK_NOT_NULL(n = ba_alloc_from_uint8(def_params->n, sizeof(def_params->n)));
    CHECK_NOT_NULL(px = ba_alloc_from_uint8(def_params->px, sizeof(def_params->px)));
    CHECK_NOT_NULL(py = ba_alloc_from_uint8(def_params->py, sizeof(def_params->py)));

    ctx = (def_params->is_onb)
            ? dstu4145_alloc_onb(def_params->f[0], def_params->a, b, n , px, py)
            : dstu4145_alloc_pb(def_params->f, 5, def_params->a, b, n , px, py);
    CHECK_NOT_NULL(ctx);

cleanup:

    ba_free(b);
    ba_free(n);
    ba_free(px);
    ba_free(py);

    return ctx;
}

Dstu4145Ctx *dstu4145_alloc(Dstu4145ParamsId params_id)
{
    Dstu4145Ctx *ctx;

    ctx = crypto_cache_get_dstu4145(params_id);
    if (ctx != NULL) {
        return ctx;
    }

    return dstu4145_alloc_new(params_id);
}

static Dstu4145ParamsCtx *dstu4145_params_alloc(const int *f, size_t f_len, int a, const ByteArray *b,
        const ByteArray *n,
        const ByteArray *px, const ByteArray *py, bool is_onb)
{
    Dstu4145ParamsCtx *params = NULL;
    WordArray *px_wa = NULL;
    WordArray *py_wa = NULL;
    WordArray *b_wa = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(f != NULL);
    CHECK_PARAM(f_len == 3 || f_len == 5);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);

    CALLOC_CHECKED(params, sizeof(Dstu4145ParamsCtx));

    params->is_onb = is_onb;

    CHECK_NOT_NULL(b_wa = wa_alloc_from_ba(b));
    CHECK_NOT_NULL(params->ec2m = ec2m_alloc(f, f_len, a, b_wa));
    wa_free(b_wa);

    CHECK_NOT_NULL(params->n = wa_alloc_from_ba(n));
    wa_change_len(params->n, params->ec2m->len);
    params->m = f[0];

    if (is_onb) {
        init_onb_params(params, f[0]);

        /* b принадлежит GF(2^m). */
        if (int_bit_len(params->ec2m->b) > params->m) {
            SET_ERROR(RET_INVALID_DSTU_PARAM_B);
        }
        DO(onb_to_pb(params, params->ec2m->b));
    } else {
        params->to_pb = NULL;
        params->to_onb = NULL;
    }

    /* Инициализация базовой точки. */
    if (py == NULL) {
        DO(dstu4145_decompress_pubkey_core(params, px, &qx, &qy));
        CHECK_NOT_NULL(px_wa = wa_alloc_from_ba(qx));
        CHECK_NOT_NULL(py_wa = wa_alloc_from_ba(qy));
    } else {
        CHECK_NOT_NULL(px_wa = wa_alloc_from_ba(px));
        CHECK_NOT_NULL(py_wa = wa_alloc_from_ba(py));
    }

    wa_change_len(px_wa, params->ec2m->len);
    wa_change_len(py_wa, params->ec2m->len);

    if (is_onb) {
        DO(onb_to_pb(params, px_wa));
        DO(onb_to_pb(params, py_wa));
    }
    CHECK_NOT_NULL(params->p = ec_point_aff_alloc(px_wa, py_wa));

    params->precomp_p = NULL;

cleanup:

    if (ret != RET_OK) {
        free(params);
        params = NULL;
    }

    wa_free(px_wa);
    wa_free(py_wa);

    ba_free(qx);
    ba_free(qy);

    return params;
}

int dstu4145_get_params(const Dstu4145Ctx *ctx, int **f, size_t *f_len, int *a, ByteArray **b, ByteArray **n,
        ByteArray **px, ByteArray **py)
{
    int ret = RET_OK;
    int len;
    int params_len;
    WordArray *px_wa = NULL;
    WordArray *py_wa = NULL;
    WordArray *b_wa = NULL;

    CHECK_PARAM(ctx != NULL);

    len = (ctx->params->ec2m->gf2m->f[2] == 0 ? 3 : 5);
    params_len = (ctx->params->ec2m->gf2m->f[0] + 7) >> 3;

    if (f_len) {
        *f_len = len;
    }

    if (f) {
        MALLOC_CHECKED(*f, len * sizeof(int));
        memcpy(*f, ctx->params->ec2m->gf2m->f, len * sizeof(int));
    }

    if (a) {
        *a = ctx->params->ec2m->a;
    }

    if (b) {
        if (ctx->params->is_onb) {
            CHECK_NOT_NULL(b_wa = wa_copy_with_alloc(ctx->params->ec2m->b));
            DO(pb_to_onb(ctx->params, b_wa));
            CHECK_NOT_NULL(*b = wa_to_ba(b_wa));
        } else {
            CHECK_NOT_NULL(*b = wa_to_ba(ctx->params->ec2m->b));
        }
        DO(ba_change_len(*b, params_len));
    }

    if (n) {
        CHECK_NOT_NULL(*n = wa_to_ba(ctx->params->n));
        DO(ba_change_len(*n, params_len));
    }

    if (px) {
        if (ctx->params->is_onb) {
            CHECK_NOT_NULL(px_wa = wa_copy_with_alloc(ctx->params->p->x));
            DO(pb_to_onb(ctx->params, px_wa));
            CHECK_NOT_NULL(*px = wa_to_ba(px_wa));
        } else {
            CHECK_NOT_NULL(*px = wa_to_ba(ctx->params->p->x));
        }
        DO(ba_change_len(*px, params_len));
    }

    if (py) {
        if (ctx->params->is_onb) {
            CHECK_NOT_NULL(py_wa = wa_copy_with_alloc(ctx->params->p->y));
            DO(pb_to_onb(ctx->params, py_wa));
            CHECK_NOT_NULL(*py = wa_to_ba(py_wa));
        } else {
            CHECK_NOT_NULL(*py = wa_to_ba(ctx->params->p->y));
        }
        DO(ba_change_len(*py, params_len));
    }

cleanup:

    wa_free(px_wa);
    wa_free(py_wa);
    wa_free(b_wa);

    return ret;
}

int dstu4145_is_onb_params(const Dstu4145Ctx *ctx, bool *is_onb_params)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(is_onb_params != NULL);

    *is_onb_params = ctx->params->is_onb;

cleanup:

    return ret;
}

int dstu4145_equals_params(const Dstu4145Ctx *param_a, const Dstu4145Ctx *param_b, bool *equals)
{
    int f_len_a, f_len_b;
    int ret = RET_OK;

    CHECK_PARAM(param_a != NULL);
    CHECK_PARAM(param_b != NULL);
    CHECK_PARAM(equals != NULL);

    if (param_a->params->is_onb != param_b->params->is_onb) {
        *equals = false;
        return RET_OK;
    }

    f_len_a = (param_a->params->ec2m->gf2m->f[2] == 0) ? 3 : 5;
    f_len_b = (param_b->params->ec2m->gf2m->f[2] == 0) ? 3 : 5;

    if ((f_len_a != f_len_b)) {
        *equals = false;
        return RET_OK;
    }

    if (memcmp(param_a->params->ec2m->gf2m->f, param_b->params->ec2m->gf2m->f, f_len_a * sizeof(int))) {
        *equals = false;
        return RET_OK;
    }

    if (param_a->params->ec2m->a != param_b->params->ec2m->a) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->ec2m->b, param_b->params->ec2m->b)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->n, param_b->params->n)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->p->x, param_b->params->p->x)) {
        *equals = false;
        return RET_OK;
    }

    if (wa_cmp(param_a->params->p->y, param_b->params->p->y)) {
        *equals = false;
        return RET_OK;
    }

    *equals = true;

cleanup:

    return ret;
}

static int dstu4145_set_verify_precomp(Dstu4145Ctx *ctx, int verify_comb_opt_level, int verify_win_opt_level)
{
    Dstu4145ParamsCtx *params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (verify_comb_opt_level == 0 && verify_win_opt_level == 0) {
        if (default_opt_level != 0) {
            verify_comb_opt_level = (default_opt_level >> 4) & 0x0f;
            verify_win_opt_level = default_opt_level & 0x0f;
        } else {
            verify_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }
    }

    if (verify_comb_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_COMB
                || ctx->precomp_q->ctx.comb->comb_width != verify_comb_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ec2m_calc_comb_precomp(params->ec2m, ctx->pub_key, verify_comb_opt_level, &ctx->precomp_q));
        }
    } else if (verify_win_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_WIN
                || ctx->precomp_q->ctx.win->win_width != verify_win_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ec2m_calc_win_precomp(params->ec2m, ctx->pub_key, verify_win_opt_level, &ctx->precomp_q));
        }
    }

cleanup:

    return ret;
}

Dstu4145Ctx *dstu4145_copy_params_with_alloc(const Dstu4145Ctx *param)
{
    int ret = RET_OK;
    size_t i;

    Dstu4145Ctx *param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CALLOC_CHECKED(param_copy, sizeof(Dstu4145Ctx));
    CALLOC_CHECKED(param_copy->params, sizeof(Dstu4145ParamsCtx));

    param_copy->params->is_onb = param->params->is_onb;
    param_copy->params->m = param->params->m;

    CHECK_NOT_NULL(param_copy->params->ec2m = ec2m_copy_with_alloc(param->params->ec2m));
    CHECK_NOT_NULL(param_copy->params->p = ec_point_copy_with_alloc(param->params->p));
    CHECK_NOT_NULL(param_copy->params->n = wa_copy_with_alloc(param->params->n));
    if (param->params->precomp_p) {
        CHECK_NOT_NULL(param_copy->params->precomp_p = ec_copy_precomp_with_alloc(param->params->precomp_p));
    }

    if (param->params->to_onb) {
        MALLOC_CHECKED(param_copy->params->to_onb, param->params->m * sizeof(WordArray *));
        for (i = 0; i < param->params->m; i++) {
            param_copy->params->to_onb[i] = wa_copy_with_alloc(param->params->to_onb[i]);
        }
    }

    if (param->params->to_pb) {
        MALLOC_CHECKED(param_copy->params->to_pb, param->params->m * sizeof(WordArray *));
        for (i = 0; i < param->params->m; i++) {
            param_copy->params->to_pb[i] = wa_copy_with_alloc(param->params->to_pb[i]);
        }
    }

    if (param->precomp_q != NULL) {
        int verify_comb_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? param->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (param->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? param->precomp_q->ctx.win->win_width : 0;
        dstu4145_set_verify_precomp(param_copy, verify_comb_opt_level, verify_win_opt_level);
    }

    return param_copy;

cleanup:

    dstu4145_free(param_copy);

    return NULL;
}

Dstu4145Ctx *dstu4145_copy_with_alloc(const Dstu4145Ctx *param)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;

    Dstu4145Ctx *param_copy = NULL;

    CHECK_PARAM(param != NULL);

    CHECK_NOT_NULL(param_copy = dstu4145_copy_params_with_alloc(param));

    if (param->prng) {
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(prng_next_bytes(param->prng, seed));
        CHECK_NOT_NULL(param_copy->prng = prng_alloc(PRNG_MODE_DSTU, seed));
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

    dstu4145_free(param_copy);
    ba_free_private(seed);

    return NULL;
}

void dstu4145_params_free(Dstu4145ParamsCtx *params)
{
    size_t i;

    if (params != NULL) {
        ec2m_free(params->ec2m);
        wa_free(params->n);
        ec_point_free(params->p);
        if (params->to_pb) {
            for (i = 0; i < params->m; i++) {
                wa_free(params->to_pb[i]);
            }
            free(params->to_pb);
        }
        if (params->to_onb) {
            for (i = 0; i < params->m; i++) {
                wa_free(params->to_onb[i]);
            }
            free(params->to_onb);
        }

        ec_precomp_free(params->precomp_p);

        free(params);
    }
}

Dstu4145Ctx *dstu4145_alloc_pb_new(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    Dstu4145Ctx *ctx = NULL;

    CHECK_PARAM(f != NULL);
    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);

    CALLOC_CHECKED(ctx, sizeof(Dstu4145Ctx));
    CHECK_NOT_NULL(ctx->params = dstu4145_params_alloc(f, f_len, a, b, n, px, py, false));

cleanup:

    if (ret != RET_OK) {
        dstu4145_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

Dstu4145Ctx *dstu4145_alloc_pb(const int *f, size_t f_len, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    Dstu4145Ctx *ctx;

    ctx = crypto_cache_get_dstu4145_pb(f, f_len, a, b, n, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return dstu4145_alloc_pb_new(f, f_len, a, b, n, px, py);
}

Dstu4145Ctx *dstu4145_alloc_onb_new(const int m, int a, const ByteArray *b, const ByteArray *n,
        const ByteArray *px, const ByteArray *py)
{
    int ret = RET_OK;
    Dstu4145Ctx *ctx = NULL;

    CHECK_PARAM(b != NULL);
    CHECK_PARAM(n != NULL);
    CHECK_PARAM(px != NULL);
    CHECK_PARAM(py != NULL);

    CALLOC_CHECKED(ctx, sizeof(Dstu4145Ctx));

    const int *f = dstu4145_get_defaut_f_onb(m);
    CHECK_PARAM(f != NULL);

    CHECK_NOT_NULL(ctx->params = dstu4145_params_alloc(f, 5, a, b, n, px, py, true));

cleanup:

    if (ret != RET_OK) {
        dstu4145_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

Dstu4145Ctx *dstu4145_alloc_onb(const int m, int a, const ByteArray *b, const ByteArray *n, const ByteArray *px,
        const ByteArray *py)
{
    Dstu4145Ctx *ctx;

    ctx = crypto_cache_get_dstu4145_onb(m, a, b, n, px, py);
    if (ctx != NULL) {
        return ctx;
    }

    return dstu4145_alloc_onb_new(m, a, b, n, px, py);
}

int dstu4145_generate_privkey(const Dstu4145Ctx *ctx, PrngCtx *prng, ByteArray **d)
{
    int ret = RET_OK;
    size_t n_bit_len;
    PrngMode mode;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(prng_get_mode(prng, &mode) == RET_OK && mode == PRNG_MODE_DSTU);
    CHECK_PARAM(d != NULL);

    n_bit_len = int_bit_len(ctx->params->n);

    CHECK_NOT_NULL(*d = ba_alloc_by_len((n_bit_len + 7) / 8));

    /* Генерация закрытого ключа. */
    do {
        DO(prng_next_bytes(prng, *d));
        DO(ba_truncate(*d, n_bit_len - 1));
    } while (ba_is_zero(*d));

cleanup:

    return ret;
}

static int dstu4145_set_sign_precomp(const Dstu4145Ctx *ctx, int sign_comb_opt_level, int sign_win_opt_level)
{
    Dstu4145ParamsCtx *params = NULL;
    int ret = RET_OK;

    params = ctx->params;

    if (sign_comb_opt_level == 0 && sign_win_opt_level == 0) {
        if (default_opt_level != 0) {
            sign_comb_opt_level = (default_opt_level >> 12) & 0x0f;
            sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        } else {
            sign_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }
    }

    if (sign_comb_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_COMB
                || params->precomp_p->ctx.comb->comb_width != sign_comb_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            DO(ec2m_calc_comb_precomp(params->ec2m, params->p, sign_comb_opt_level, &params->precomp_p));
        }
    } else if (sign_win_opt_level > 0) {
        if (params->precomp_p == NULL || params->precomp_p->type != EC_PRECOMP_TYPE_WIN
                || params->precomp_p->ctx.win->win_width != sign_win_opt_level) {
            ec_precomp_free(params->precomp_p);
            params->precomp_p = NULL;
            DO(ec2m_calc_win_precomp(params->ec2m, params->p, sign_win_opt_level, &params->precomp_p));
        }
    }

cleanup:

    return ret;
}

int dstu4145_get_pubkey(const Dstu4145Ctx *ctx, const ByteArray *d, ByteArray **qx, ByteArray **qy)
{
    WordArray *d_wa = NULL;
    const Dstu4145ParamsCtx *params;
    ECPoint *Q = NULL;
    size_t q_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    params = ctx->params;

    CHECK_NOT_NULL(d_wa = wa_alloc_from_ba(d));

    /* 0 < d < n */
    if (int_is_zero(d_wa) || int_cmp(d_wa, params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(d_wa, ctx->params->ec2m->len);

    /* Получение открытого ключа. */
    CHECK_NOT_NULL(Q = ec_point_alloc(params->ec2m->len));
    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }

        DO(dstu4145_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }
    DO(ec2m_dual_mul_opt(params->ec2m, params->precomp_p, d_wa, NULL, NULL, Q));

    /* Инвертируем точку эллиптической кривой. */
    gf2m_mod_add(Q->x, Q->y, Q->y);

    if (params->is_onb) {
        DO(pb_to_onb(ctx->params, Q->x));
        DO(pb_to_onb(ctx->params, Q->y));
    }

    q_len = (ctx->params->m + 7) / 8;

    CHECK_NOT_NULL(*qx = wa_to_ba(Q->x));
    CHECK_NOT_NULL(*qy = wa_to_ba(Q->y));

    DO(ba_change_len(*qx, q_len));
    DO(ba_change_len(*qy, q_len));

cleanup:

    ec_point_free(Q);
    wa_free_private(d_wa);

    return ret;
}

int dstu4145_compress_pubkey(const Dstu4145Ctx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q)
{
    int ret = RET_OK;
    int trace;
    size_t q_len;
    ECPoint *ec_point = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    DO(public_key_to_ec_point(ctx->params, qx, qy, &ec_point));

    q_len = (ctx->params->m + 7) / 8;
    if (int_is_zero(ec_point->x)) {
        CHECK_NOT_NULL(*q = ba_alloc_by_len(qx->len));
        memset((*q)->buf, 0, q_len);
        ret = RET_OK;
        goto cleanup;
    }

    CHECK_NOT_NULL(*q = ba_alloc_from_uint8(qx->buf, qx->len));

    gf2m_mod_inv(ctx->params->ec2m->gf2m, ec_point->x, ec_point->x);
    gf2m_mod_mul(ctx->params->ec2m->gf2m, ec_point->x, ec_point->y, ec_point->y);
    trace = gf2m_mod_trace(ctx->params->ec2m->gf2m, ec_point->y);

    if (((*q)->buf[0] ^ trace) & 1) {
        (*q)->buf[0] ^= 1;
    }

    DO(ba_change_len(*q, q_len));

cleanup:

    ec_point_free(ec_point);

    return ret;
}

int dstu4145_decompress_pubkey(const Dstu4145Ctx *ctx, const ByteArray *q, ByteArray **qx, ByteArray **qy)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    DO(dstu4145_decompress_pubkey_core(ctx->params, q, qx, qy));

cleanup:

    return ret;
}

int dstu4145_init_sign(Dstu4145Ctx *ctx, const ByteArray *d, PrngCtx *prng)
{
    ByteArray *seed = NULL;
    int ret = RET_OK;
    PrngMode mode;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(prng_get_mode(prng, &mode) == RET_OK && mode == PRNG_MODE_DSTU);
    CHECK_PARAM(d != NULL);

    if (ctx->params == NULL) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    if (ctx->pub_key) {
        ctx->verify_status = false;
        ec_point_free(ctx->pub_key);
        ctx->pub_key = NULL;
    }

    if (ctx->precomp_q != NULL) {
        int verify_comb_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_q->ctx.win->win_width : 0;

        ec_precomp_free(ctx->precomp_q);
        ctx->precomp_q = NULL;
        dstu4145_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level);
    }

    if (ctx->priv_key) {
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    CHECK_NOT_NULL(ctx->priv_key = wa_alloc_from_ba(d));
    wa_change_len(ctx->priv_key, ctx->params->ec2m->len);

    if (int_is_zero(ctx->priv_key)) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    /* 0 < d < n, хотя для ключей ДСТУ 4145-2002: L(d) < L(n), используется более слабое ограничение d < n, для ключей по ISO 15946-3. */
    if (int_cmp(ctx->priv_key, ctx->params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    DO(prng_next_bytes(prng, seed));

    if (ctx->prng != NULL) {
        DO(prng_seed(ctx->prng, seed));
    } else {
        CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DSTU, seed));
    }

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }

        dstu4145_set_sign_precomp(ctx, 0, sign_win_opt_level);
    }

    ctx->sign_status = true;

cleanup:

    if (ret != RET_OK) {
        ctx->sign_status = false;
    }
    ba_free(seed);

    return ret;
}

int dstu4145_set_opt_level(Dstu4145Ctx *ctx, OptLevelId opt_level)
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

    DO(dstu4145_set_sign_precomp(ctx, sign_comb_opt_level, sign_win_opt_level));
    DO(dstu4145_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));

cleanup:

    return ret;
}

int dstu4145_sign(const Dstu4145Ctx *ctx, const ByteArray *hash, ByteArray **r, ByteArray **s)
{
    const Dstu4145ParamsCtx *params;
    WordArray *e = NULL;
    ByteArray *e_ba = NULL;
    WordArray *res = NULL;
    WordArray *wr = NULL;
    WordArray *ws = NULL;
    WordArray *h = NULL;
    ByteArray *r_ba = NULL;
    ByteArray *s_ba = NULL;
    ECPoint *rec = NULL;
    bool is_onb;
    int ret = RET_OK;
    size_t words;
    size_t ln;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(hash->len == 32);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    params = ctx->params;

    if (!ctx->sign_status) {
        SET_ERROR(RET_INVALID_CTX_MODE);
    }

    words = params->ec2m->len;

    is_onb = params->is_onb;

    CHECK_NOT_NULL(h = wa_alloc_from_ba(hash));
    int_truncate(h, params->m);

    wa_change_len(h, words);

    if (is_onb) {
        DO(onb_to_pb(params, h));
    }

    if (int_is_zero(h)) {
        h->buf[0] = 1;
    }

    CHECK_NOT_NULL(e = wa_alloc(words));
    CHECK_NOT_NULL(e_ba = ba_alloc_by_len(words * WORD_BYTE_LENGTH));
    CHECK_NOT_NULL(wr = wa_alloc(words));
    CHECK_NOT_NULL(res = wa_alloc(2 * words));
    CHECK_NOT_NULL(ws = wa_alloc(words));
    CHECK_NOT_NULL(rec = ec_point_alloc(words));

    do {
        do {
            DO(prng_next_bytes(ctx->prng, e_ba));
            DO(wa_from_ba(e_ba, e));
            int_truncate(e, int_bit_len(params->n) - 1);

            DO(ec2m_dual_mul_opt(params->ec2m, params->precomp_p, e, NULL, NULL, rec));

            gf2m_mod_mul(params->ec2m->gf2m, rec->x, h, wr);

            if (is_onb) {
                DO(pb_to_onb(params, wr));
            }

            int_truncate(wr, int_bit_len(params->n) - 1);

        } while (int_is_zero(wr));

        /* ws = (e + rd)(mod n). */
        wa_change_len(ctx->priv_key, wr->len);
        int_mul(ctx->priv_key, wr, res);
        int_div(res, params->n, NULL, ws);
        if (int_add(e, ws, ws) > 0 || int_cmp(ws, params->n) >= 0) {
            int_sub(ws, params->n, ws);
        }

    } while (int_is_zero(ws));

    ln = (int_bit_len(params->n) + 7) >> 3;

    CHECK_NOT_NULL(r_ba = wa_to_ba(wr));
    DO(ba_change_len(r_ba, ln));
    CHECK_NOT_NULL(s_ba = wa_to_ba(ws));
    DO(ba_change_len(s_ba, ln));

    *r = r_ba;
    *s = s_ba;

    r_ba = NULL;
    s_ba = NULL;

cleanup:

    wa_free_private(e);
    wa_free(res);
    wa_free(wr);
    wa_free(ws);
    wa_free(h);
    ba_free(e_ba);
    ba_free(r_ba);
    ba_free(s_ba);
    ec_point_free(rec);

    return ret;
}

int dstu4145_init_verify(Dstu4145Ctx *ctx, const ByteArray *qx, const ByteArray *qy)
{
    int ret = RET_OK;
    int verify_comb_opt_level;
    int verify_win_opt_level;
    ECPoint *pub_key = NULL;
    bool need_update_precomp_q = false;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);

    if (ctx->priv_key) {
        ctx->sign_status = false;
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

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
            verify_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }
        need_update_precomp_q = true;
    }

    if (need_update_precomp_q) {
        DO(dstu4145_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));
    }

    if (ctx->params->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = DSTU4145_DEFAULT_WIN_WIDTH;
        }

        DO(dstu4145_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    ctx->verify_status = true;

cleanup:

    ec_point_free(pub_key);
    if (ret != RET_OK) {
        ctx->verify_status = false;
    }

    return ret;
}

int dstu4145_verify(const Dstu4145Ctx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s)
{
    const Dstu4145ParamsCtx *params;
    WordArray *ws = NULL;
    WordArray *wr = NULL;
    WordArray *r1 = NULL;
    WordArray *h = NULL;
    ECPoint *r_point = NULL;
    const EcGf2mCtx *ec2m;
    size_t n_bit_len;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(hash->len == 32);
    CHECK_PARAM(r != NULL);
    CHECK_PARAM(s != NULL);

    params = ctx->params;

    if (ctx->verify_status == 0) {
        ERROR_CREATE(RET_INVALID_CTX_MODE);
    }

    ec2m = params->ec2m;

    /* Проверка ЭЦП. */
    n_bit_len = int_bit_len(ctx->params->n);

    if (((ba_get_len(s) + ba_get_len(r)) & 1) == 1) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(wr = wa_alloc_from_ba(r));
    CHECK_NOT_NULL(ws = wa_alloc_from_ba(s));

    /* 0 < wr < n і 0 < ws < n, иначе подпись неверная. */
    if ((int_cmp(wr, ctx->params->n) >= 0) || (int_cmp(ws, ctx->params->n) >= 0)
            || int_is_zero(wr) || int_is_zero(ws)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

    CHECK_NOT_NULL(h = wa_alloc_from_ba(hash));
    int_truncate(h, params->m);
    wa_change_len(h, ec2m->len);

    if (params->is_onb) {
        DO(onb_to_pb(params, h));
    }

    if (int_is_zero(h)) {
        h->buf[0] = 1;
    }

    CHECK_NOT_NULL(r_point = ec_point_alloc(ec2m->len));

    DO(ec2m_dual_mul_opt(ec2m, ctx->params->precomp_p, ws, ctx->precomp_q, wr, r_point));

    CHECK_NOT_NULL(r1 = wa_alloc(ec2m->len));
    gf2m_mod_mul(ec2m->gf2m, r_point->x, h, r1);

    if (params->is_onb) {
        DO(pb_to_onb(ctx->params, r1));
    }

    int_truncate(r1, n_bit_len - 1);

    if (!int_equals(r1, wr)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }

cleanup:

    wa_free(wr);
    wa_free(ws);
    wa_free(r1);
    wa_free(h);
    ec_point_free(r_point);

    return ret;
}

/**
 * Возвращает кофактор.
 *
 * @param ctx параметры ДСТУ 4145
 * @param cofactor кофактор
 */
static void dstu4145ec_get_cofactor(const Dstu4145ParamsCtx *params, WordArray *cofactor)
{
    size_t len = params->ec2m->len;
    word_t carry;
    WordArray *s = NULL;
    WordArray *one = NULL;
    WordArray *power_two = NULL;
    int ret = RET_OK;

    CHECK_PARAM(params != NULL);
    CHECK_PARAM(cofactor != NULL);

    CHECK_NOT_NULL(one = wa_alloc_with_one(len));
    CHECK_NOT_NULL(power_two = wa_alloc(len));

    int_lshift(one, params->m, power_two);
    int_sqrt(power_two, cofactor);
    carry = int_add(cofactor, cofactor, cofactor);
    carry += int_add(cofactor, one, cofactor);
    carry += int_add(cofactor, power_two, cofactor);

    CHECK_NOT_NULL(s = wa_copy_with_alloc(cofactor));
    wa_change_len(s, 2 * len);
    s->buf[len] = carry;
    int_div(s, params->n, s, NULL);

    DO(wa_copy_part(s, 0, len, cofactor));

cleanup:

    wa_free(s);
    wa_free(one);
    wa_free(power_two);
}

int dstu4145_dh(const Dstu4145Ctx *ctx, bool with_cofactor, const ByteArray *d, const ByteArray *qx,
        const ByteArray *qy, ByteArray **zx, ByteArray **zy)
{
    int ret = RET_OK;
    WordArray *x = NULL;
    WordArray *cofactor = NULL;
    ECPoint *rq = NULL;
    ECPoint *r = NULL;
    size_t len;
    size_t z_len;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(d != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(zx != NULL);
    CHECK_PARAM(zy != NULL);

    len = ctx->params->ec2m->len;

    /* Получение кофактора. */
    CHECK_NOT_NULL(cofactor = wa_alloc(len));
    dstu4145ec_get_cofactor(ctx->params, cofactor);

    /* Инициализация открытого ключа удаленной стороны. */
    DO(public_key_to_ec_point(ctx->params, qx, qy, &rq));

    /* Проверка того что открытый ключ лежит в подгруппе порядка n. */
    CHECK_NOT_NULL(r = ec_point_alloc(len));
    ec2m_mul(ctx->params->ec2m, rq, cofactor, r);
    if (int_is_zero(r->x) && int_is_zero(r->y)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    /* Проверка корректности закрытого ключа (0 < d < n). */
    CHECK_NOT_NULL(x = wa_alloc_from_ba(d));
    if (int_cmp(x, ctx->params->n) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    wa_change_len(x, ctx->params->ec2m->len);

    /* Получение общего секрета. */
    ec2m_mul(ctx->params->ec2m, rq, x, r);

    if (with_cofactor) {
        ec2m_mul(ctx->params->ec2m, r, cofactor, r);
    }

    if (ctx->params->is_onb) {
        DO(pb_to_onb(ctx->params, r->x));
        DO(pb_to_onb(ctx->params, r->y));
    }

    z_len = (ctx->params->m + 7) / 8;
    CHECK_NOT_NULL(*zx = wa_to_ba(r->x));
    CHECK_NOT_NULL(*zy = wa_to_ba(r->y));
    DO(ba_change_len(*zx, z_len));
    DO(ba_change_len(*zy, z_len));

    ret = RET_OK;

cleanup:

    wa_free_private(x);
    wa_free(cofactor);
    ec_point_free(r);
    ec_point_free(rq);

    return ret;
}

void dstu4145_free(Dstu4145Ctx *ctx)
{
    if (ctx) {
        wa_free_private(ctx->priv_key);
        dstu4145_params_free(ctx->params);
        prng_free(ctx->prng);
        ec_point_free(ctx->pub_key);
        ec_precomp_free(ctx->precomp_q);
        free(ctx);
    }
}
