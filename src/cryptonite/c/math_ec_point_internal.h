/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MATH_EC_POINT_H
#define CRYPTONITE_MATH_EC_POINT_H

#include "word_internal.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct ECPoint_st {
    WordArray *x;
    WordArray *y;
    WordArray *z;
} ECPoint;

ECPoint *ec_point_alloc(size_t len);
ECPoint *ec_point_aff_alloc(const WordArray *px, const WordArray *py);
ECPoint *ec_point_proj_alloc(const WordArray *px, const WordArray *py, const WordArray *pz);
void ec_point_zero(ECPoint *p);
void ec_point_copy(const ECPoint *a, ECPoint *out);
ECPoint *ec_point_copy_with_alloc(const ECPoint *a);
void ec_point_free(ECPoint *p);

#ifdef  __cplusplus
}
#endif

#endif
