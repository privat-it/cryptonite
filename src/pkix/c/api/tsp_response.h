/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_TSP_RESPONSE_H
#define CRYPTONITE_PKI_API_TSP_RESPONSE_H

#include "pkix_structs.h"
#include "sign_adapter.h"
#include "digest_adapter.h"
#include "verify_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT TimeStampResp_t *tsresp_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param tsresp об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void tsresp_free(TimeStampResp_t *tsresp);

/**
 * Повертає байтове представлення об'єкта в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsresp мітка часу (відповідь)
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_encode(const TimeStampResp_t *tsresp, ByteArray **out);

/**
 * Ініціалізує мітку часу з DER-представлення.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsresp мітка часу (відповідь)
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_decode(TimeStampResp_t *tsresp, const ByteArray *in);

/**
 * Повертає статус формування мітки.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsresp мітка часу (відповідь)
 * @param status створюємий об'єкт статуса формування мітки
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_get_status(const TimeStampResp_t *tsresp, PKIStatusInfo_t **status);

/**
 * Встановлює статус формування мітки.
 *
 * @param tsresp мітка часу (відповідь)
 * @param status статус формування мітки
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_set_status(TimeStampResp_t *tsresp, const PKIStatusInfo_t *status);

/**
 * Повертає сформовану мітку часу.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsresp мітка часу (відповідь)
 * @param ts_token створюємий об'єкт мітки часу
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_get_ts_token(const TimeStampResp_t *tsresp, ContentInfo_t **ts_token);

/**
 * Встановлює сформовану мітку часу.
 *
 * @param tsresp мітка часу (відповідь)
 * @param ts_token мітка часу
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_set_ts_token(TimeStampResp_t *tsresp, const ContentInfo_t *ts_token);

/**
 * Виконує перевірку мітки часу.
 *
 * @param tsresp мітка часу (відповідь)
 * @param da адаптер обчислення геша
 * @param va адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsresp_verify(const TimeStampResp_t *tsresp, const DigestAdapter *da, const VerifyAdapter *va);

#ifdef __cplusplus
}
#endif

#endif
