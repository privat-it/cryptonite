/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __OCSP_REQUEST_ENGINE_H__
#define __OCSP_REQUEST_ENGINE_H__

#include <stdbool.h>
#include <time.h>

#include "oids.h"
#include "sign_adapter.h"
#include "digest_adapter.h"
#include "verify_adapter.h"
#include "pkix_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_ocsp_req_engine Генератор запиту статусу сертифіката
 * @{
 */

typedef struct OcspRequestEngine_st OcspRequestEngine;


/**
 * Створює та ініціалізує контекст .
 *
 * @param ctx вказівник на створюваний контекст
 * @param is_nonce_present прапорець наявності мітки
 * @param root_va посилання на кореневий адаптер перевірки підпису
 * @param ocsp_va посилання на адаптер перевірки підпису OCSP сертифікату
 * @param subject_sa посилання на адаптер підпису суб'єкту, який формує запит
 * @param da адаптер гешування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspreq_alloc(bool is_nonce_present, const VerifyAdapter *root_va, const VerifyAdapter *ocsp_va,
                                     const SignAdapter *subject_sa, const DigestAdapter *da, OcspRequestEngine **ctx);

/**
 * Очищує контекст.
 *
 * @param ctx контекст
 */
CRYPTONITE_EXPORT void eocspreq_free(OcspRequestEngine *ctx);

/**
 * Додає ідентифікатор сертифікату для перевірки статусу.
 *
 * @param ctx контекст
 * @param sn серійний номер сертифікату, який перевіряється
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspreq_add_sn(OcspRequestEngine *ctx, const CertificateSerialNumber_t *sn);

/**
 * Додає ідентифікатор сертифікату.
 *
 * @param ctx контекст
 * @param cert сертифікат, який перевіряється
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspreq_add_cert(OcspRequestEngine *ctx, const Certificate_t *cert);

/**
 * Генерує запит для відправки OCSP сервісу.
 *
 * @param ctx контекст
 * @param rnd випадкові байти
 * @param req вказівник на створюваний запит
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspreq_generate(OcspRequestEngine *ctx, ByteArray *rnd, OCSPRequest_t **req);

/**
 * Перевіряє відповідь OCSP сервісу.
 *
 * @param ocsp_resp декодована відповідь
 * @param current_time поточний час (GMT)
 * @param timeout максимальний час таймаута у хвилинах
 *
 * @return код помилки
 *         RET_EOCSPRESP_NOT_SUCCESSFUL статус відповіді відмінний від SUCCESSFUL
 *         RET_EOCSPREQ_ADAPTER_ISNOT_OCSP у відповіді не заданий nextUpdate
 */
CRYPTONITE_EXPORT int eocspreq_validate_resp(const OCSPResponse_t *ocsp_resp, time_t current_time, int timeout);

/**
 * Створює запит для OCSP сервісу на основі сертифікату користувача та корневого сертифікату.
 *
 * @param root_cert кореневий сертифікат
 * @param user_cert користувацький сертифікат
 * @param ocsp_req сгенерований OCSP запит
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eocspreq_generate_from_cert(const Certificate_t *root_cert, const Certificate_t *user_cert,
                                                  OCSPRequest_t **ocsp_req);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
