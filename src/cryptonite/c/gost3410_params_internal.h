//
// Created by paradaimu on 9/6/18.
//

#ifndef CRYPTONITE_GOST3410_PARAMS_INTERNAL_H
#define CRYPTONITE_GOST3410_PARAMS_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>

#include "byte_array.h"
#include "word_internal.h"
#include "math_ec_point_internal.h"
#include "math_ec2m_internal.h"
#include "prng.h"
#include "gost3410.h"
#include "math_ecp_internal.h"

typedef struct Dstu4145DefaultParamsCtx_st {
    uint8_t p[32];
    uint8_t a[32];
    uint8_t b[32];
    uint8_t q[32];
    uint8_t px[32];
    uint8_t py[32];
} Gost3410DefaultParamsCtx;

typedef struct Gost3410ParamsCtx_st {
    WordArray *p;
    WordArray *a;
    WordArray *b;
    WordArray *q;
    ECPoint *P;
} Gost3410ParamsCtx;

struct Gost3410Ctx_st {
    GfpCtx *gfp;
    GfpCtx *gfq;
    EcGfpCtx *ecgfp;
    Gost3410ParamsCtx *params;     /* Параметри ДСТУ 4145. */
    PrngCtx *prng;                 /* Контекст ГПСЧ. */
    WordArray *priv_key;           /* закритий ключ. */
    ECPoint *pub_key;              /* відкритий ключ. */
    EcPrecomp *precomp_q;
    EcPrecomp *precomp_p;
    bool sign_status;              /* Готов ли контекст для формування підпису. */
    bool verify_status;            /* Готов ли контекст для перевірки підпису. */
};

const Gost3410DefaultParamsCtx *gost3410_get_defaut_params(Gost3410ParamsId params_id);

#endif //CRYPTONITE_GOST3410_PARAMS_INTERNAL_H
