/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_CIPHER_ADAPTER_H
#define CRYPTONITE_PKI_CRYPTO_CIPHER_ADAPTER_H

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CipherAdapter_st;

/* Вказівник на функцію шифрування */
typedef int (ca_encrypt_f)(const struct CipherAdapter_st *ca, const ByteArray *key, const ByteArray *src,
        ByteArray **dst);

/* Вказівник на функцію розшифрування */
typedef int (ca_decrypt_f)(const struct CipherAdapter_st *ca, const ByteArray *key, const ByteArray *src,
        ByteArray **dst);

/* Вказівник на функцію отримання алгоритму шифрування */
typedef int (ca_get_alg_f)(const struct CipherAdapter_st *ca, AlgorithmIdentifier_t **alg_id);

/* Вказівник на функцію очистки контекста */
typedef void (ca_free_f)(struct CipherAdapter_st *ca);

typedef struct CipherAdapter_st {
    ca_encrypt_f *encrypt;
    ca_decrypt_f *decrypt;
    ca_get_alg_f *get_alg;
    ca_free_f *free;
    const void *const ctx;
} CipherAdapter;

#ifdef __cplusplus
}
#endif

#endif
