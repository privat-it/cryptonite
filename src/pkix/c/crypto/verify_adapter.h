/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_VERIFY_ADAPTER_H
#define CRYPTONITE_PKI_CRYPTO_VERIFY_ADAPTER_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

struct VerifyAdapter_st;

/* Вказівник на функцію перевірки ЕЦП */
typedef int (va_verify_data_f)(const struct VerifyAdapter_st *va, const ByteArray *data, const ByteArray *sign);

/* Вказівник на функцію перевірки ЕЦП */
typedef int (va_verify_hash_f)(const struct VerifyAdapter_st *va, const ByteArray *hash, const ByteArray *sign);

/* Вказівник на функцію отримання SubjectPublicKeyInfo */
typedef int (va_get_pub_key_f)(const struct VerifyAdapter_st *va, SubjectPublicKeyInfo_t **pub_key);

/* Індикатор наявності сертифікату */
typedef int (va_has_cert_f)(const struct VerifyAdapter_st *va, bool *has_cert);

/* Вказівник на функцію установки сертифікату */
typedef int (va_set_cert_f)(const struct VerifyAdapter_st *va, const Certificate_t *cert);

/* Вказівник на функцію отримання сертифікату */
typedef int (va_get_cert_f)(const struct VerifyAdapter_st *va, Certificate_t **cert);

/* Вказівник на функцію отримання алгоритму гешування */
typedef int (va_get_digest_alg_f)(const struct VerifyAdapter_st *va, DigestAlgorithmIdentifier_t **digest_alg_id);

/* Вказівник на функцію встановляння алгоритму гешування */
typedef int (va_set_digest_alg_f)(struct VerifyAdapter_st *va, const DigestAlgorithmIdentifier_t *alg);

/* Вказівник на функцію отримання алгоритму підпису */
typedef int (va_get_sign_alg_f)(const struct VerifyAdapter_st *va, SignatureAlgorithmIdentifier_t **sign_alg_id);

/* Вказівник на функцію очистки контексту */
typedef void (verify_free_f)(struct VerifyAdapter_st *va);

typedef struct VerifyAdapter_st {
    va_verify_data_f *verify_data;
    va_verify_hash_f *verify_hash;
    va_get_pub_key_f *get_pub_key;
    va_has_cert_f *has_cert;
    va_get_cert_f *get_cert;
    va_set_cert_f *set_cert;
    va_get_digest_alg_f *get_digest_alg;
    va_set_digest_alg_f *set_digest_alg;
    va_get_sign_alg_f *get_sign_alg;
    verify_free_f *free;
    const void *const ctx;
} VerifyAdapter;

#ifdef __cplusplus
}
#endif

#endif
