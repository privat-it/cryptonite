/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_ECDSA_INTERNAL_H
#define CRYPTONITE_ECDSA_INTERNAL_H

#include "ecdsa.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Створює контекст ECDSA за параметрами.
 *
 * @param p порядок скінченного простого поля GF(p)
 * @param a коефіцієнт a у рівнянні еліптичної кривої
 * @param b коефіцієнт b у рівнянні еліптичної кривої
 * @param q порядок базової точки
 * @param px X-координата базової точки
 * @param py Y-координата базової точки
 *
 * @return контекст ECDSA
 */
EcdsaCtx *ecdsa_alloc_ext_new(const ByteArray *p, const ByteArray *a, const ByteArray *b, const ByteArray *q,
        const ByteArray *px, const ByteArray *py);

#ifdef  __cplusplus
}
#endif

#endif
