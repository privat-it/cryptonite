/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CERT_REQUEST_ENGINE_H
#define CERT_REQUEST_ENGINE_H

#include "pkix_structs.h"
#include "sign_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_cert_req_engine Генератор запиту сертифікату PKCS #10
 * @{
 */
typedef struct CertificateRequestEngine_st CertificateRequestEngine;

/**
 * Ініціалізує контекст випуску запиту сертифікату.
 *
 * @param sa посилання на ініціалізований адаптер підпису видавця сертифікату, який випускається
 * @param ctx контекст випуску запиту сертифікату
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_request_alloc(const SignAdapter *sa, CertificateRequestEngine **ctx);

/**
 * Ініціалізує контекст випуску запиту сертифікату.
 *
 * @param ctx контекст випуску запиту сертифікату
 * @param subject_name  ім'я суб'єкта у вигляді форматованого рядка, кожен атрибут імені
 *                      визначаєтья фігурними дужками <code>{}</code>, ключ значення
 *                      кожного атрибуту імені розділяється через <code>=</code>
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_request_set_subj_name(CertificateRequestEngine *ctx, const char *subject_name);

/**
 * Ініціалізує контекст випуску запиту сертифікату.
 *
 * @param ctx контекст випуску запиту сертифікату
 * @param dns dns для розширення альтернативного імені суб'єкта
 * @param email email для розширення альтернативного імені суб'єкта
 * @return код помилки
 */

CRYPTONITE_EXPORT int ecert_request_set_subj_alt_name(CertificateRequestEngine *ctx, const char *dns,
                                                      const char *email);

/**
 * Ініціалізує контекст випуску запиту сертифікату.
 *
 * @param ctx контекст випуску запиту сертифікату
 * @param subject_attr  атрибути суб'єкту у вигляді форматованого рядка, кожен атрибут
 *                      визначаєтья фігурними дужками <code>{}</code>, ключ значення
 *                      кожного атрибуту імені розділяється через <code>=</code>
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_request_set_subj_dir_attr(CertificateRequestEngine *ctx, const char *subject_attr);

/**
 * Ініціалізує контекст випуску запиту сертифікату.
 *
 * @param ctx контекст випуску запиту сертифікату
 * @param ext розширення
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_request_add_ext(CertificateRequestEngine *ctx, const Extension_t *ext);

/**
 * Генерує запит сертифікації з переданих даних.
 *
 * @param ctx контекст випуску запиту сертифікату
 * @param cert_req      запит сертифікації
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecert_request_generate(CertificateRequestEngine *ctx, CertificationRequest_t **cert_req);

/**
 * Очищує контекст випуску запиту сертифікату
 *
 * @param ctx контекст випуску запиту сертифікату
 */
CRYPTONITE_EXPORT void ecert_request_free(CertificateRequestEngine *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
