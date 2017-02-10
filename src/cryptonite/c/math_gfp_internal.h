/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_GFP_H
#define CRYPTONITE_MATH_GFP_H

#include <stdbool.h>

#include "word_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct GfpCtx_st {
    WordArray *p;
    WordArray *one;
    WordArray *two;
    WordArray *invert_const;
} GfpCtx;

GfpCtx *gfp_alloc(const WordArray *p);
GfpCtx *gfp_copy_with_alloc(const GfpCtx *ctx);
void gfp_init(GfpCtx *ctx, const WordArray *p);
void gfp_mod_add(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod_sub(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod(const GfpCtx *ctx, const WordArray *a, WordArray *out);
void gfp_mod_mul(const GfpCtx *ctx, const WordArray *a, const WordArray *b, WordArray *out);
void gfp_mod_sqr(const GfpCtx *ctx, const WordArray *a, WordArray *out);
WordArray *gfp_mod_inv(const GfpCtx *ctx, const WordArray *a);
void gfp_mod_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x, WordArray *out);
void gfp_mod_dual_pow(const GfpCtx *ctx, const WordArray *a, const WordArray *x,
        const WordArray *b, const WordArray *y, WordArray *out);

/**
 * Вычисляет один из квадратных корней элемента поля GF(p).
 *
 * @param a элемент поля
 * @param out массив для a^(1/2) (mod p)
 *
 * @return можно ли получить корень
 */
bool gfp_mod_sqrt(const GfpCtx *ctx, const WordArray *a, WordArray *out);

void gfp_free(GfpCtx *ctx);

WordArray *gfp_mod_inv_core(const WordArray *in, const WordArray *p);

#ifdef  __cplusplus
}
#endif

#endif
