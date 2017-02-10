/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __OCSP_RESPONSE_ENGINE_H__
#define __OCSP_RESPONSE_ENGINE_H__

#include <stdbool.h>
#include <time.h>

#include "sign_adapter.h"
#include "digest_adapter.h"
#include "oids.h"
#include "verify_adapter.h"
#include "pkix_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_ocsp_resp_engine Генератор відповіді на запит статуса сертифікату
 * @{
 */

typedef enum {
    OCSP_RESPONSE_BY_HASH_KEY = 0,
    OCSP_RESPONSE_BY_NAME = 1
} ResponderIdType;

typedef struct OcspResponseEngine_st OcspResponseEngine;

/**
 * Ініціалізує генератор OCSP відповідей.
 *
 * @param ctx вказівник на створюваний контекст генератору відповіді
 * @param root_va кореневий адаптер перевірки підпису
 * @param ocsp_sign адаптер підпису OCSP відповіді
 * @param crls списки відкликаних сертифікатів для перевірки статусу
 * @param da адаптер гешування для перевірки ідентифікатора сертифікату
 * @param next_up_req прапорець зазначення часу наступного оновлення
 * @param crl_reason_req прапорець зазначення причини відклику сертифікату
 * @param id_type тип ідентифікатора
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_alloc(const VerifyAdapter *root_va, const SignAdapter *ocsp_sign,
                                      const CertificateLists_t *crls, const DigestAdapter *da, bool next_up_req, bool crl_reason_req, ResponderIdType id_type,
                                      OcspResponseEngine **ctx);

/**
 * Встановлює прапорець необхідності перевірки підпису в запиті.
 *
 * @param ctx контекст генератора відповіді
 * @param sign_required прапорець перевірки підпису в запиті
 */
CRYPTONITE_EXPORT void eocspresp_set_sign_required(OcspResponseEngine *ctx, bool sign_required);

/**
 * Встановлює нові списки відкликаних сертифікатів для перевірки статуса сертифікатів.
 *
 * @param ctx контекст генератора відповіді
 * @param crls списки відкликаних сертифікатів
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_set_crls(OcspResponseEngine *ctx, const CertificateLists_t *crls);

/**
 * Генерує OCSP відповідь по отриманому запиту.
 *
 * @param ctx контекст генератора відповіді
 * @param req запит на перевірку статусу сертифіката
 * @param req_va адаптер перевірки підпису запиту, якщо він присутній
 * @param current_time поточний час
 * @param resp вказівник на створювану відповідь, який містить інформацію про сертифікати або інформацію про помилку
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_generate(OcspResponseEngine *ctx, const OCSPRequest_t *req, const VerifyAdapter *req_va,
                                         time_t current_time, OCSPResponse_t **resp);

/**
 * Формує відповідь OCSP зі статусом невірного запиту.
 *
 * @param resp вказівник на створювану відповідь OCSP зі статусом невірного запиту
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_form_malformed_req(OCSPResponse_t **resp);

/**
 * Формує відповідь OCSP зі статусом внутрішньої помилки.
 *
 * @param resp вказівник на створювану відповідь OCSP зі статусом внутрішньої помилки
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_form_internal_error(OCSPResponse_t **resp);

/**
 * Формує відповідь OCSP зі статусом перевантаження.
 *
 * @param resp вказівник на створювану відповідь OCSP зі статусом перевантаження
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_form_try_later(OCSPResponse_t **resp);

/**
 * Формує відповідь OCSP зі статусом неавторизованого запиту.
 *
 * @param resp вказівник на створювану відповідь OCSP зі статусом неавторизованого запиту
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspresp_form_unauthorized(OCSPResponse_t **resp);

/**
 * Очищує контекст генератора відповіді.
 *
 * @param ctx контекст генератора відповіді
 */
CRYPTONITE_EXPORT void eocspresp_free(OcspResponseEngine *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
