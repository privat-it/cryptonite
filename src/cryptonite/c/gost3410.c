//
// Created by paradaimu on 9/6/18.
//

#include "gost3410.h"
#include "gost3410_params_internal.h"
#include "math_gfp_internal.h"
#include "math_ec_point_internal.h"
#include "math_ec_precomp_internal.h"
#include "macros_internal.h"
#include "math_int_internal.h"
#include "math_ecp_internal.h"
#include "crypto_cache_internal.h"
#include "cryptonite_errors.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/gost3410.c"

#define GOST3410_DEFAULT_WIN_WIDTH 5
#define GOST3410_MODULE_SIZE 32

static int gost3410_set_sign_precomp(Gost3410Ctx *ctx, int sign_comb_opt_level, int sign_win_opt_level)
{
    int ret = RET_OK;

    if (sign_comb_opt_level == 0 && sign_win_opt_level == 0) {
        if (default_opt_level != 0) {
            sign_comb_opt_level = (default_opt_level >> 12) & 0x0f;
            sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        } else {
            sign_win_opt_level = GOST3410_DEFAULT_WIN_WIDTH;
        }
    }

    if (sign_comb_opt_level > 0) {
        if (ctx->precomp_p == NULL || ctx->precomp_p->type != EC_PRECOMP_TYPE_COMB
            || ctx->precomp_p->ctx.comb->comb_width != sign_comb_opt_level) {
            ec_precomp_free(ctx->precomp_p);
            ctx->precomp_p = NULL;
            DO(ecp_calc_comb_precomp(ctx->ecgfp, ctx->params->P, sign_comb_opt_level, &ctx->precomp_p));
        }
    } else if (sign_win_opt_level > 0) {
        if (ctx->precomp_p == NULL || ctx->precomp_p->type != EC_PRECOMP_TYPE_WIN
            || ctx->precomp_p->ctx.win->win_width != sign_win_opt_level) {
            ec_precomp_free(ctx->precomp_p);
            ctx->precomp_p = NULL;
            DO(ecp_calc_win_precomp(ctx->ecgfp,ctx->params->P, sign_win_opt_level, &ctx->precomp_p));
        }
    }

cleanup:

    return ret;
}

static int gost3410_set_verify_precomp(Gost3410Ctx *ctx, int verify_comb_opt_level, int verify_win_opt_level)
{
    int ret = RET_OK;

    if (verify_comb_opt_level == 0 && verify_win_opt_level == 0) {
        if (default_opt_level != 0) {
            verify_comb_opt_level = (default_opt_level >> 4) & 0x0f;
            verify_win_opt_level = default_opt_level & 0x0f;
        } else {
            verify_win_opt_level = GOST3410_DEFAULT_WIN_WIDTH;
        }
    }

    if (verify_comb_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_COMB
            || ctx->precomp_q->ctx.comb->comb_width != verify_comb_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ecp_calc_comb_precomp(ctx->ecgfp, ctx->pub_key, verify_comb_opt_level, &ctx->precomp_q));
        }
    } else if (verify_win_opt_level > 0) {
        if (ctx->precomp_q == NULL || ctx->precomp_q->type != EC_PRECOMP_TYPE_WIN
            || ctx->precomp_q->ctx.win->win_width != verify_win_opt_level) {
            ec_precomp_free(ctx->precomp_q);
            ctx->precomp_q = NULL;
            DO(ecp_calc_win_precomp(ctx->ecgfp, ctx->pub_key, verify_win_opt_level, &ctx->precomp_q));
        }
    }

cleanup:

    return ret;
}


static void gost3410_params_free(Gost3410ParamsCtx *params)
{
    if (params == NULL) {
        return;
    }

    ec_point_free(params->P);
    wa_free(params->p);
    wa_free(params->a);
    wa_free(params->b);
    wa_free(params->q);

    free(params);
}

Gost3410Ctx *gost3410_alloc_with_params(const ByteArray *p, const ByteArray *a, const ByteArray *b,
                                        const ByteArray *q, const ByteArray *px, const ByteArray *py)
{
    Gost3410Ctx *ctx = NULL;
    Gost3410ParamsCtx *paramsCtx = NULL;
    WordArray *px_wa = NULL;
    WordArray *py_wa = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(paramsCtx, sizeof(Gost3410ParamsCtx));

    CHECK_NOT_NULL(paramsCtx->p = wa_alloc_from_ba(p));
    CHECK_NOT_NULL(paramsCtx->a = wa_alloc_from_ba(a));
    CHECK_NOT_NULL(paramsCtx->b = wa_alloc_from_ba(b));
    CHECK_NOT_NULL(paramsCtx->q = wa_alloc_from_ba(q));
    CHECK_NOT_NULL(px_wa = wa_alloc_from_ba(px));
    CHECK_NOT_NULL(py_wa = wa_alloc_from_ba(py));
    CHECK_NOT_NULL(paramsCtx->P = ec_point_aff_alloc(px_wa, py_wa));
    CALLOC_CHECKED(ctx, sizeof(Gost3410Ctx));

    ctx->params = paramsCtx;
    paramsCtx = NULL;
    ctx->precomp_p = NULL;
    ctx->precomp_q = NULL;

    CHECK_NOT_NULL(ctx->ecgfp = ecp_alloc(ctx->params->p, ctx->params->a, ctx->params->b));
    CHECK_NOT_NULL(ctx->gfq = gfp_alloc(ctx->params->q));
    CHECK_NOT_NULL(ctx->gfp = gfp_alloc(ctx->params->p));

cleanup:

    if (ret != RET_OK) {
        gost3410_free(ctx);
        ctx = NULL;
    }

    wa_free(px_wa);
    wa_free(py_wa);
    gost3410_params_free(paramsCtx);

    return ctx;
}

Gost3410Ctx *gost3410_alloc(Gost3410ParamsId params_id)
{
    const Gost3410DefaultParamsCtx *def_params;
    ByteArray *p = NULL;
    ByteArray *a = NULL;
    ByteArray *b = NULL;
    ByteArray *q = NULL;
    ByteArray *px = NULL;
    ByteArray *py = NULL;
    Gost3410Ctx *ctx = NULL;
    int ret = RET_OK;

    def_params = gost3410_get_defaut_params(params_id);
    if (def_params == NULL) {
        ERROR_CREATE(RET_INVALID_PARAM);
        return NULL;
    }

    CHECK_NOT_NULL(p = ba_alloc_from_uint8_be(def_params->p, sizeof(def_params->p)));
    CHECK_NOT_NULL(a = ba_alloc_from_uint8_be(def_params->a, sizeof(def_params->a)));
    CHECK_NOT_NULL(b = ba_alloc_from_uint8_be(def_params->b, sizeof(def_params->b)));
    CHECK_NOT_NULL(q = ba_alloc_from_uint8_be(def_params->q, sizeof(def_params->q)));
    CHECK_NOT_NULL(px = ba_alloc_from_uint8_be(def_params->px, sizeof(def_params->px)));
    CHECK_NOT_NULL(py = ba_alloc_from_uint8_be(def_params->py, sizeof(def_params->py)));

    CHECK_NOT_NULL(ctx = gost3410_alloc_with_params(p, a, b, q, px, py));

    ctx->sign_status = false;
    ctx->verify_status = false;

cleanup:
    if (ret != RET_OK) {
        gost3410_free(ctx);
    }
    ba_free(p);
    ba_free(a);
    ba_free(b);
    ba_free(q);
    ba_free(px);
    ba_free(py);

    return ctx;
}

void gost3410_free(Gost3410Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    gost3410_params_free(ctx->params);
    ec_precomp_free(ctx->precomp_p);
    ec_precomp_free(ctx->precomp_q);
    prng_free(ctx->prng);
    wa_free_private(ctx->priv_key);
    ec_point_free(ctx->pub_key);
    gfp_free(ctx->gfp);
    gfp_free(ctx->gfq);
    ecp_free(ctx->ecgfp);

    free(ctx);
}

int gost3410_init_sign(Gost3410Ctx *ctx, const ByteArray *d, PrngCtx *prng)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;
    WordArray *d_wa = NULL;

    ctx->sign_status = false;

    if (ctx->pub_key != NULL || ctx->verify_status == true) {
        ctx->verify_status = false;
        ec_point_free(ctx->pub_key);
        ctx->pub_key = NULL;
    }

    CHECK_NOT_NULL(d_wa = wa_alloc_from_ba(d));
    if (int_is_zero(d_wa) || int_cmp(d_wa, ctx->params->q) >= 0) {
        SET_ERROR(RET_INVALID_PRIVATE_KEY);
    }

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    DO(prng_next_bytes(prng, seed));

    if (ctx->prng != NULL) {
        DO(prng_seed(ctx->prng, seed));
    } else {
        CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    }

    if (ctx->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = GOST3410_DEFAULT_WIN_WIDTH;
        }

        DO(gost3410_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    if (ctx->priv_key != NULL) {
        wa_free(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    ctx->priv_key = wa_alloc_from_ba(d);

    ctx->sign_status = true;

cleanup:

    if (ret != RET_OK) {

    }
    ba_free(seed);
    wa_free(d_wa);

    return ret;
}

int gost3410_sign(Gost3410Ctx *ctx, const ByteArray *hash, ByteArray **rOut, ByteArray **sOut)
{
    int ret = RET_OK;
    WordArray *hash_wa = NULL;
    WordArray *e = NULL;
    WordArray *k = NULL;
    WordArray *r = NULL;
    WordArray *s = NULL;
    WordArray *s2 = NULL;
    ECPoint *C = NULL;

    if (!ctx->sign_status) {
        return RET_CONTEXT_NOT_READY;
    }

    CHECK_NOT_NULL(hash_wa = wa_alloc_from_ba(hash));
    CHECK_NOT_NULL(e = wa_alloc_with_zero(ctx->gfq->p->len));

    wa_change_len(hash_wa, ctx->gfq->p->len << 1);

    gfp_mod(ctx->gfq, hash_wa, e);

    if (int_is_zero(e)) {
        wa_one(e);
    }

    do {
        do {
            wa_free(k);
            wa_free(r);
            ec_point_free(C);

            CHECK_NOT_NULL(k = wa_alloc_with_zero(ctx->params->q->len));

            DO(int_rand(ctx->prng, ctx->params->q, k));

            CHECK_NOT_NULL(C = ec_point_alloc(ctx->ecgfp->len));
            DO(ecp_dual_mul_opt(ctx->ecgfp, ctx->precomp_p, k, NULL, NULL, C));

            CHECK_NOT_NULL(r = wa_alloc_with_zero(ctx->params->q->len));
            wa_change_len(C->x, C->x->len << 1);
            gfp_mod(ctx->gfq, C->x, r);
            wa_change_len(C->x, C->x->len >> 1);

        } while (int_is_zero(r));


        CHECK_NOT_NULL(s = wa_alloc_with_zero(ctx->priv_key->len << 1));
        CHECK_NOT_NULL(s2 = wa_alloc_with_zero(ctx->priv_key->len << 1));

        int_mul(r, ctx->priv_key, s);
        int_mul(e, k, s2);
        int_add(s, s2, s2);

        wa_change_len(s, s->len >> 1);

        gfp_mod(ctx->gfq, s2, s);

    } while (int_is_zero(s));


    (*rOut) = wa_to_ba(r);
    (*sOut) = wa_to_ba(s);

cleanup:

    wa_free(hash_wa);
    wa_free(e);
    wa_free(k);
    wa_free(r);
    wa_free(s);
    wa_free(s2);
    ec_point_free(C);

    return ret;
}

int gost3410_get_pubkey(Gost3410Ctx *ctx, const ByteArray *d, ByteArray **Qx, ByteArray **Qy)
{
    int ret = RET_OK;
    WordArray *d_wa = NULL;
    ECPoint *pubkey = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    CHECK_PARAM(ctx != NULL)
    CHECK_PARAM(d != NULL)
    CHECK_PARAM(Qx != NULL)
    CHECK_PARAM(Qy != NULL)

    CHECK_NOT_NULL(d_wa = wa_alloc_from_ba(d));

    if (int_is_zero(d_wa) || (int_cmp(d_wa, ctx->params->q) >= 0)) {
        return RET_INVALID_PRIVATE_KEY;
    }

    CHECK_NOT_NULL(pubkey = ec_point_alloc(ctx->params->P->x->len));

    if (ctx->precomp_p == NULL) {
        int sign_win_opt_level = (default_opt_level >> 8) & 0x0f;
        if (sign_win_opt_level == 0) {
            sign_win_opt_level = GOST3410_DEFAULT_WIN_WIDTH;
        }
        DO(gost3410_set_sign_precomp(ctx, 0, sign_win_opt_level));
    }

    DO(ecp_dual_mul_opt(ctx->ecgfp, ctx->precomp_p, d_wa, NULL, NULL, pubkey));
    if (!ecp_is_on_curve(ctx->ecgfp, pubkey->x, pubkey->y)) {
        SET_ERROR(RET_POINT_NOT_ON_CURVE);
    }

    CHECK_NOT_NULL (qx = wa_to_ba(pubkey->x));
    CHECK_NOT_NULL (qy = wa_to_ba(pubkey->y));

    (*Qx) = qx;
    (*Qy) = qy;

    qx = NULL;
    qy = NULL;

cleanup:


    ba_free(qx);
    ba_free(qy);
    wa_free(d_wa);
    ec_point_free(pubkey);

    return ret;
}

static int public_key_to_ec_point(const Gost3410Ctx *ctx, const ByteArray *qx, const ByteArray *qy, ECPoint **q)
{
    WordArray *wqx = NULL;
    WordArray *wqy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);

    CHECK_NOT_NULL(wqx = wa_alloc_from_ba(qx));
    CHECK_NOT_NULL(wqy = wa_alloc_from_ba(qy));

    /* Проверка корректности открытого ключа 0 <= qx < p, 0 < qy < p */
    if (int_cmp(wqx, ctx->ecgfp->gfp->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_cmp(wqy, ctx->ecgfp->gfp->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_is_zero(wqy)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    wa_change_len(wqx, ctx->params->p->len);
    wa_change_len(wqy, ctx->params->p->len);

    /* Открытый ключ принадлежит эллиптической кривой. */
    if (!ecp_is_on_curve(ctx->ecgfp, wqx, wqy)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    CHECK_NOT_NULL(*q = ec_point_aff_alloc(wqx, wqy));

cleanup:

    wa_free(wqx);
    wa_free(wqy);

    return ret;
}

int gost3410_compress_pubkey(Gost3410Ctx *ctx, const ByteArray *qx, const ByteArray *qy, ByteArray **q, int *last_qy_bit)
{
    ECPoint *ec_point = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(q != NULL);
    CHECK_PARAM(last_qy_bit != NULL);

    DO(public_key_to_ec_point(ctx, qx, qy, &ec_point));
    CHECK_NOT_NULL(*q = ba_alloc_from_uint8(qx->buf, qx->len));
    *last_qy_bit = int_get_bit(ec_point->y, 0);

cleanup:

    ec_point_free(ec_point);

    return ret;
}

int gost3410_decompress_pubkey(Gost3410Ctx *ctx, const ByteArray *q, int last_qy_bit, ByteArray **qx,
                               ByteArray **qy)
{
    WordArray *x = NULL;
    WordArray *y = NULL;
    const GfpCtx *gfp;
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
    wa_change_len(x, ctx->params->p->len);

    CHECK_NOT_NULL(y = wa_alloc(ctx->params->p->len));

    gfp = ctx->ecgfp->gfp;
    if (int_cmp(x, gfp->p) >= 0 || int_is_zero(x)) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    /* Восстановление точки эллиптической кривой. */
    wa_free(y);
    y = NULL;

    CHECK_NOT_NULL(y = wa_alloc(ctx->params->p->len));
    gfp_mod_sqr(gfp, x, y);
    gfp_mod_add(gfp, y, ctx->ecgfp->a, y);
    gfp_mod_mul(gfp, x, y, y);
    gfp_mod_add(gfp, y, ctx->ecgfp->b, y);
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

int gost3410_init_verify(Gost3410Ctx *ctx, const ByteArray *qx, const ByteArray *qy)
{
    int ret = RET_OK;
    WordArray *qx_wa = NULL;
    WordArray *qy_wa = NULL;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(qx != NULL);
    CHECK_PARAM(qy != NULL);
    CHECK_PARAM(qx->len == qy->len && qx->len == GOST3410_MODULE_SIZE);

    if (ctx->priv_key != NULL || ctx->sign_status == true) {
        ctx->sign_status = false;
        wa_free_private(ctx->priv_key);
        ctx->priv_key = NULL;
    }

    if (ctx->prng != NULL) {
        prng_free(ctx->prng);
        ctx->prng = NULL;
    }

    CHECK_NOT_NULL(qx_wa = wa_alloc_from_ba(qx));
    CHECK_NOT_NULL(qy_wa = wa_alloc_from_ba(qy));

    CHECK_NOT_NULL(ctx->pub_key = ec_point_aff_alloc(qx_wa, qy_wa));

    if (int_is_zero(qx_wa) || int_cmp(qx_wa, ctx->params->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (int_is_zero(qy_wa) || int_cmp(qx_wa, ctx->params->p) >= 0) {
        SET_ERROR(RET_INVALID_PUBLIC_KEY);
    }

    if (!ecp_is_on_curve(ctx->ecgfp, qx_wa, qy_wa)) {
        SET_ERROR(RET_POINT_NOT_ON_CURVE);
    }

    if (ctx->precomp_q != NULL) {
        int verify_comb_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_q->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (ctx->precomp_q->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_q->ctx.win->win_width : GOST3410_DEFAULT_WIN_WIDTH;

        ec_precomp_free(ctx->precomp_q);
        ctx->precomp_q = NULL;
        DO(gost3410_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));
    } else {
        DO(gost3410_set_verify_precomp(ctx, 0, GOST3410_DEFAULT_WIN_WIDTH));
    }

    if (ctx->precomp_p != NULL) {
        int verify_comb_opt_level = (ctx->precomp_p->type == EC_PRECOMP_TYPE_COMB) ? ctx->precomp_p->ctx.comb->comb_width : 0;
        int verify_win_opt_level = (ctx->precomp_p->type == EC_PRECOMP_TYPE_WIN) ? ctx->precomp_p->ctx.win->win_width : GOST3410_DEFAULT_WIN_WIDTH;

        ec_precomp_free(ctx->precomp_p);
        ctx->precomp_p = NULL;
        DO(gost3410_set_sign_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));
    } else {
        DO(gost3410_set_sign_precomp(ctx, 0, GOST3410_DEFAULT_WIN_WIDTH));
    }

    ctx->verify_status = true;

cleanup:

    if (ret != RET_OK) {
        ec_precomp_free(ctx->precomp_q);
        ec_precomp_free(ctx->precomp_p);
        ec_point_free(ctx->pub_key);
        ctx->pub_key = NULL;
        ctx->precomp_q = NULL;
        ctx->precomp_p = NULL;
    }

    wa_free(qx_wa);
    wa_free(qy_wa);

    return ret;
}

//#define PR printf("%s:%d\n", __FILE__, __LINE__); fflush(stdout);

int gost3410_verify(Gost3410Ctx *ctx, const ByteArray *hash, const ByteArray *r, const ByteArray *s)
{
    WordArray *e = NULL;
    WordArray *v = NULL;
    WordArray *z1 = NULL;
    WordArray *z2 = NULL;
    WordArray *r_wa = NULL;
    WordArray *s_wa = NULL;
    WordArray *R = NULL;
    WordArray *hash_wa = NULL;
    ECPoint *C = NULL;
    int ret = RET_OK;

    if (!ctx->verify_status) {
        return RET_CONTEXT_NOT_READY;
    }

    CHECK_NOT_NULL(r_wa = wa_alloc_from_ba(r));
    CHECK_NOT_NULL(s_wa = wa_alloc_from_ba(s));

    if ((int_cmp(r_wa, ctx->params->p) >= 0)
        || (int_cmp(s_wa, ctx->params->p) >= 0)
        || int_is_zero(r_wa)
        || int_is_zero(s_wa)) {
        return RET_INVALID_PARAM;
    }

    CHECK_NOT_NULL(hash_wa = wa_alloc_from_ba(hash));

    CHECK_NOT_NULL(e = wa_alloc(hash_wa->len));

    wa_change_len(hash_wa, hash_wa->len << 1);

    if (ctx->gfq == NULL) {
        CHECK_NOT_NULL(ctx->gfq = gfp_alloc(ctx->params->q));
    }

    gfp_mod(ctx->gfq, hash_wa, e);

    if (int_is_zero(e)) {
        wa_one(e);
    }

    CHECK_NOT_NULL(v = gfp_mod_inv(ctx->gfq, e));

    CHECK_NOT_NULL(z1 = wa_alloc(v->len));
    CHECK_NOT_NULL(z2 = wa_alloc(v->len));

    gfp_mod_mul(ctx->gfq, v, s_wa, z1);
    gfp_mod_mul(ctx->gfq, v, r_wa, z2);
    gfp_mod_sub(ctx->gfq, ctx->gfq->p, z2, z2);

    CHECK_NOT_NULL(C = ec_point_alloc(v->len));

    DO(ecp_dual_mul_opt(ctx->ecgfp, ctx->precomp_p, z1, ctx->precomp_q, z2, C));

    CHECK_NOT_NULL(R = wa_alloc(v->len));

    wa_change_len(C->x, C->x->len << 1);

    gfp_mod(ctx->gfq, C->x, R);

    if (!int_equals(R, r_wa)) {
        SET_ERROR(RET_VERIFY_FAILED);
    }


cleanup:

    ec_point_free(C);
    wa_free(e);
    wa_free(v);
    wa_free(z1);
    wa_free(z2);
    wa_free(r_wa);
    wa_free(s_wa);
    wa_free(R);
    wa_free(hash_wa);

    return ret;
}

int gost3410_set_opt_level(Gost3410Ctx *ctx, OptLevelId opt_level)
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

    DO(gost3410_set_sign_precomp(ctx, sign_comb_opt_level, sign_win_opt_level));
    DO(gost3410_set_verify_precomp(ctx, verify_comb_opt_level, verify_win_opt_level));

cleanup:

    return ret;
}
