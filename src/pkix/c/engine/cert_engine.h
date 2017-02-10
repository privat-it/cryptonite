/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __CERT_ENGINE_H__
#define __CERT_ENGINE_H__

#include <stdbool.h>
#include <time.h>

#include "pkix_structs.h"
#include "digest_adapter.h"
#include "sign_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CertificateEngine_st CertificateEngine;

/**
 * Ініціалізує контекст випуску сертифікатів.
 *
 * @param sa посилання на ініціалізований адаптер підпису видавця сертифікату, який випускається
 * @param da посилання на ініціалізований адаптер гешування для обчислення ідентифікаторів ключів
 * @param is_self_signed ознака самопідписанного сертифікату
 * @param ctx контекст випуску сертифікатів
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_alloc(const SignAdapter *sa, const DigestAdapter *da, bool is_self_signed,
                                  CertificateEngine **ctx);

/**
 * Очищує контекст випуску сертифікатів.
 *
 * @param ctx контекст випуску сертифікатів
 */
CRYPTONITE_EXPORT void ecert_free(CertificateEngine *ctx);

/**
 * Генерує сертифікат.
 *
 * @param ctx контекст випуску сертифікатів
 * @param req запит на сертифікацію
 * @param ver версія сертифікату, який випускається
 * @param cert_sn серійний номер сертифікату, який випускається
 * @param not_before термін початку використання ключа
 * @param not_after термін закінчення використання ключа
 * @param exts список розширень сертифікату
 * @param cert випущений сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_generate(const CertificateEngine *ctx, const CertificationRequest_t *req, int ver,
        const ByteArray *cert_sn, const time_t *not_before, const time_t *not_after, const Extensions_t *exts,
        Certificate_t **cert);

#ifdef __cplusplus
}
#endif

#endif
