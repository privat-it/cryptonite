/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_DIGEST_ADAPTER_H
#define CRYPTONITE_PKI_CRYPTO_DIGEST_ADAPTER_H

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

struct DigestAdapter_st;

/* Вказівник на функцію виробки геш вектору */
typedef int (da_update_f)(const struct DigestAdapter_st *da, const ByteArray *src);

/* Вказівник на функцію виробки геш вектору */
typedef int (da_final_f)(const struct DigestAdapter_st *da, ByteArray **dig);

/* Вказівник на функцію отримання алгоритму гешування */
typedef int (da_get_alg_f)(const struct DigestAdapter_st *da, DigestAlgorithmIdentifier_t **alg_id);

/* Вказівник на функцію очистки контексту */
typedef void (da_free_f)(struct DigestAdapter_st *da);

typedef struct DigestAdapter_st {
    da_update_f *update;
    da_final_f *final;
    da_get_alg_f *get_alg;
    da_free_f *free;
    const void *const ctx;
} DigestAdapter;

#ifdef __cplusplus
}
#endif

#endif
