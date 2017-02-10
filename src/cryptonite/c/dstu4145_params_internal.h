/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU4145_PARAMS_H
#define CRYPTONITE_DSTU4145_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

#include "byte_array.h"
#include "word_internal.h"
#include "math_ec_point_internal.h"
#include "math_ec2m_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dstu4145DefaultParamsCtx_st {
    int f[5];
    int a;
    uint8_t b[64];
    uint8_t n[64];
    uint8_t px[64];
    uint8_t py[64];
    bool is_onb;
} Dstu4145DefaultParamsCtx;

typedef struct Dstu4145ParamsCtx_st {
    bool is_onb;
    ECPoint *p;
    EcGf2mCtx *ec2m;
    WordArray *n;                  /* Порядок циклической подгруппы группы точек еліптичної кривої. */
    size_t m;                      /* Степень основного поля. */
    WordArray **to_pb;             /* Матрица для преобразования представления елемента з ОНБ у ПБ. */
    WordArray **to_onb;            /* Матрица для преобразования представления елемента з ПБ у ОНБ. */
    EcPrecomp *precomp_p;
} Dstu4145ParamsCtx;

struct Dstu4145Ctx_st {
    Dstu4145ParamsCtx *params;     /* Параметри ДСТУ 4145. */
    PrngCtx *prng;                 /* Контекст ГПСЧ. */
    WordArray *priv_key;           /* закритий ключ. */
    ECPoint *pub_key;              /* відкритий ключ. */
    EcPrecomp *precomp_q;
    bool sign_status;              /* Готов ли контекст для формування підпису. */
    bool verify_status;            /* Готов ли контекст для перевірки підпису. */
};

const Dstu4145DefaultParamsCtx *dstu4145_get_defaut_params(Dstu4145ParamsId params_id);

const int *dstu4145_get_defaut_f_onb(int m);

int init_onb_params(Dstu4145ParamsCtx *params, int m);

/**
 * Преобразовывает елемент з ОНБ в ПБ.
 *
 * @param params Параметри ДСТУ
 * @param x елемент поля
 */
int onb_to_pb(const Dstu4145ParamsCtx *params, WordArray *x);

/**
 * Выполняет преобразование элемента поля GF(2^m) из ПБ в ОНБ.
 *
 * @param params параметры криптосистемы
 * @param x элемент поля
 */
int pb_to_onb(const Dstu4145ParamsCtx *params, WordArray *x);

int dstu4145_decompress_pubkey_core(const Dstu4145ParamsCtx *params, const ByteArray *q, ByteArray **qx,
        ByteArray **qy);

#ifdef  __cplusplus
}
#endif

#endif
