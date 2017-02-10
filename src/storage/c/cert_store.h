/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CERT_STORE_H
#define CERT_STORE_H

#include "byte_array.h"
#include "Certificate.h"
#include "Certificates.h"

/** Структура сховища сертифікатів. */
typedef struct CertStore_st CertStore_t;

CRYPTONITE_EXPORT int cert_store_set_default_path(const char *path);

CRYPTONITE_EXPORT CertStore_t *cert_store_alloc(const char *path);

/**
 * Зберігає сертифікат в кеш плагіну.
 *
 * @param store сховище
 * @param prefix префікс перед ім'ям сертифікату
 * @param cert сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_store_add_certificate(CertStore_t *store, const char *prefix, const Certificate_t *cert);

/**
 * Зберігає сертифікати в кеш плагіну.
 *
 * @param store сховище
 * @param prefix префікс перед ім'ям сертифікату
 * @param certs сертифікати
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_store_add_certificates(CertStore_t *store, const char *prefix, const Certificates_t *certs);

CRYPTONITE_EXPORT int cert_store_get_certificates_by_alias(CertStore_t *store, const char *alias,
        Certificates_t **certs);

CRYPTONITE_EXPORT int cert_store_get_certificate_by_pubkey_and_usage(CertStore_t *store, const ByteArray *pubkey,
        int keyusage, Certificate_t **cert);

CRYPTONITE_EXPORT void cert_store_free(CertStore_t *store);

#endif  /* CERT_STORE_H */
