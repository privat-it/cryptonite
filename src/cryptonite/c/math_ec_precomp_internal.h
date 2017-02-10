/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_EC_PRECOMP_H
#define CRYPTONITE_MATH_EC_PRECOMP_H

#include "math_ec_point_internal.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef enum EcPrecompType_st {
    EC_PRECOMP_TYPE_WIN,
    EC_PRECOMP_TYPE_COMB
} EcPrecompType;

typedef struct EcPrecompWin_st {
    ECPoint **precomp;
    int precomp_len;
    int win_width;
} EcPrecompWin;

typedef struct EcPrecompComb_st {
    ECPoint **precomp;
    int comb_width;
} EcPrecompComb;

/** Предварительные обчислення. */
typedef struct EcPrecomp_st {
    EcPrecompType type;
    union {
        EcPrecompWin *win;
        EcPrecompComb *comb;
    } ctx;
} EcPrecomp;

/**
 * Створює копію контексту попередніх обчислень.
 *
 * @param ctx контекст попередні обчислення
 * @return копія контексту
 */
EcPrecomp *ec_copy_precomp_with_alloc(EcPrecomp *precomp_p);

void ec_precomp_free(EcPrecomp *precomp);

#ifdef  __cplusplus
}
#endif

#endif
