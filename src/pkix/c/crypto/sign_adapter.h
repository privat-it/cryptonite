/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_SIGN_ADAPTER_H
#define CRYPTONITE_PKI_CRYPTO_SIGN_ADAPTER_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SignAdapter_st;

/* Вказівник на функцію виробки ЕЦП */
typedef int (sa_sign_data_f)(const struct SignAdapter_st *sa, const ByteArray *data, ByteArray **sign);

/* Вказівник на функцію виробки ЕЦП */
typedef int (sa_sign_hash_f)(const struct SignAdapter_st *sa, const ByteArray *hash, ByteArray **sign);

/* Вказівник на функцію отримання SubjectPublicKeyInfo */
typedef int (sa_get_pub_key_f)(const struct SignAdapter_st *sa, SubjectPublicKeyInfo_t **pub_key);

/* Індикатор наявності сертифікату */
typedef int (sa_has_cert_f)(const struct SignAdapter_st *sa, bool *has_cert);

/* Вказівник на функцію установки сертифікату */
typedef int (sa_set_cert_f)(struct SignAdapter_st *sa, const Certificate_t *cert);

/* Вказівник на функцію установки алгоритму гешування */
typedef int (sa_set_digest_alg_f)(struct SignAdapter_st *sa, const DigestAlgorithmIdentifier_t *alg);

/* Вказівник на функцію отримання сертифікату */
typedef int (sa_get_cert_f)(const struct SignAdapter_st *sa, Certificate_t **cert);

/* Вказівник на функцію отримання алгоритму гешування */
typedef int (sa_get_digest_alg_f)(const struct SignAdapter_st *sa, DigestAlgorithmIdentifier_t **digest_alg_id);

/* Вказівник на функцію отримання алгоритму підпису */
typedef int (sa_get_sign_alg_f)(const struct SignAdapter_st *sa, SignatureAlgorithmIdentifier_t **sign_alg_id);

/* Вказівник на функцію очистки контексту */
typedef void (sa_free_f)(struct SignAdapter_st *sa);

typedef struct SignAdapter_st {
    sa_sign_data_f *sign_data;
    sa_sign_hash_f *sign_hash;
    sa_get_pub_key_f *get_pub_key;
    sa_has_cert_f *has_cert;
    sa_set_cert_f *set_cert;
    sa_set_digest_alg_f *set_digest_alg;
    sa_get_cert_f *get_cert;
    sa_get_digest_alg_f *get_digest_alg;
    sa_get_sign_alg_f *get_sign_alg;
    sa_free_f *free;
    void *ctx;
} SignAdapter;

#ifdef __cplusplus
}
#endif

#endif
