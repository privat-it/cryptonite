/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_TSP_REQUEST_H
#define CRYPTONITE_PKI_API_TSP_REQUEST_H

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT TimeStampReq_t *tsreq_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param tsreq об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void tsreq_free(TimeStampReq_t *tsreq);

/**
 * Повертає байтове представлення об'єкта в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_encode(const TimeStampReq_t *tsreq, ByteArray **out);

/**
 * Ініціалізує мітку часу з DER-представлення.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_decode(TimeStampReq_t *tsreq, const ByteArray *in);

/**
 * Повертає відбиток повідомлення.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param mess_impr створюваний об'єкт відбитка повідомлення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_get_message(const TimeStampReq_t *tsreq, MessageImprint_t **mess_impr);

/**
 * Встановлює відбиток повідомлення.
 *
 * @param tsreq мітка часу (запит)
 * @param mess_impr відбиток повідомлення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_set_message(TimeStampReq_t *tsreq, const MessageImprint_t *mess_impr);

/**
 * Повертає ідентифікатор  політики формування мітки часу.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param req_policy створюваний об'єкт ідентифікатора політики
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_get_policy(const TimeStampReq_t *tsreq, OBJECT_IDENTIFIER_t **req_policy);

/**
 * Встановлює ідентифікатор  політики формування мітки часу.
 *
 * @param tsreq мітка часу (запит)
 * @param req_policy ідентифікатор політики
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_set_policy(TimeStampReq_t *tsreq, const OBJECT_IDENTIFIER_t *req_policy);

/**
 * Повертає ідентифікатор запиту.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param nonce створюваний об'єкт ідентифікатора запита
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_get_nonce(const TimeStampReq_t *tsreq, INTEGER_t **nonce);

/**
 * Встановлює ідентифікатор запиту.
 *
 * @param tsreq мітка часу (запит)
 * @param nonce ідентифікатор запиту
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_set_nonce(TimeStampReq_t *tsreq, const INTEGER_t *nonce);

/**
 * Генерує унікальний ідентифікатор на основі системного часу.
 *
 * @param tsreq мітка часу (запит)
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_generate_nonce(TimeStampReq_t *tsreq);

/**
 * Повертає прапорець вимоги сертифікату TSP у відповіді.
 *
 * @param tsreq мітка часу (запит)
 * @param cert_req прапорець вимоги сертифікату TSP
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_get_cert_req(const TimeStampReq_t *tsreq, bool *cert_req);

/**
 * Встановлює прапорець вимоги сертифікату TSP у відповіді.
 *
 * @param tsreq мітка часу (запит)
 * @param cert_req прапорець вимоги сертифікату TSP
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_set_cert_req(TimeStampReq_t *tsreq, bool cert_req);

/**
 * Повертає версію синтаксиса.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param tsreq мітка часу (запит)
 * @param version створюваний об'єкт версії
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int tsreq_get_version(const TimeStampReq_t *tsreq, INTEGER_t **version);

#ifdef __cplusplus
}
#endif

#endif
