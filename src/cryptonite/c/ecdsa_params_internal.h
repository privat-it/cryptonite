/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_ECDSA_PARAMS_H
#define CRYPTONITE_ECDSA_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "prng.h"
#include "word_internal.h"
#include "math_ec_point_internal.h"
#include "math_ecp_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct EcdsaDefaultParamsCtx_st {
    int len;
    uint8_t a[72];        /**< Коэффициент a в уравнении эллиптической кривой. */
    uint8_t b[72];        /**< Коэффициент b в уравнении эллиптической кривой. */
    uint8_t p[72];        /**< Порядок конечного простого поля. */
    uint8_t q[72];        /**< Порядок подгруппы точек эллиптической кривой. */
    uint8_t px[72];       /**< Базовая точка эллиптической кривой. */
    uint8_t py[72];       /**< Базовая точка эллиптической кривой. */
} EcdsaDefaultParamsCtx;

typedef struct EcdsaParamsCtx_st {
    ECPoint *p;
    EcGfpCtx *ecp;
    GfpCtx *gfq;
    size_t len;
    EcPrecomp *precomp_p;
} EcdsaParamsCtx;

struct EcdsaCtx_st {
    EcdsaParamsCtx *params;
    PrngCtx *prng;
    WordArray *priv_key;
    ECPoint *pub_key;
    EcPrecomp *precomp_q;
    bool sign_status;
    bool verify_status;
};

const EcdsaDefaultParamsCtx *ecdsa_get_defaut_params(EcdsaParamsId params_id);

#ifdef  __cplusplus
}
#endif

#endif
