/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_DH_ADAPTER_H
#define CRYPTONITE_PKI_CRYPTO_DH_ADAPTER_H

#include "byte_array.h"
#include "pkix_structs.h"


#ifdef __cplusplus
extern "C" {
#endif

struct DhAdapter_st;

/* Вказівник на функцію отримання відкритого ключа */
typedef int (dha_get_pub_key_f)(const struct DhAdapter_st *dha, ByteArray **pub_key);

/* Вказівник на функцію обчислення спільного секрету. */
typedef int (dha_dh_f)(const struct DhAdapter_st *dha, const ByteArray *pub_key, ByteArray **zx, ByteArray **zy);

/* Вказівник на функцію отримання алгоритму гешування */
typedef int (dha_get_alg_f)(const struct DhAdapter_st *dha, AlgorithmIdentifier_t **alg);

/* Вказівник на функцію очистки контексту */
typedef void (dha_free_f)(struct DhAdapter_st *dha);

typedef struct DhAdapter_st {
    dha_dh_f *dh;
    dha_get_alg_f *get_alg;
    dha_get_pub_key_f *get_pub_key;
    dha_free_f *free;
    const void *const ctx;
} DhAdapter;

#ifdef __cplusplus
}
#endif

#endif
