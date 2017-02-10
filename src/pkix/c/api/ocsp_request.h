/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_OCSP_REQUEST_H
#define CRYPTONITE_PKI_API_OCSP_REQUEST_H

#include "pkix_structs.h"
#include "verify_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT OCSPRequest_t *ocspreq_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param ocspreq об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void ocspreq_free(OCSPRequest_t *ocspreq);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspreq OCSP (запит)
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_encode(const OCSPRequest_t *ocspreq, ByteArray **out);

/**
 * Ініціалізує OCSP запит з DER-представлення.
 *
 * @param ocspreq OCSP запит
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_decode(OCSPRequest_t *ocspreq, const ByteArray *in);

/**
 * Повертає інформацію запита.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspreq OCSP запит
 * @param tbsreq створюваний об'єкт запита TBS
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_get_tbsreq(const OCSPRequest_t *ocspreq, TBSRequest_t **tbsreq);

/**
 * Встановлює інформацію запита.
 *
 * @param ocspreq OCSP запит
 * @param tbsreq запит TBS
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_set_tbsreq(OCSPRequest_t *ocspreq, const TBSRequest_t *tbsreq);

/**
 * Повертає опціональний підпис.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ocspreq OCSP запит
 * @param sign створюваний об'єкт підпису або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_get_sign(const OCSPRequest_t *ocspreq, Signature_t **sign);

/**
 * Встановлює опціональний підпис.
 *
 * @param ocspreq OCSP запит
 * @param sign опціональний підпис
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_set_sign(OCSPRequest_t *ocspreq, const Signature_t *sign);


/**
 * Визначає наявність підпису запита.
 *
 * @param ocspreq OCSP запит
 * @param has_sign прапорець наявності підпису запита
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_has_sign(const OCSPRequest_t *ocspreq, bool *has_sign);

/**
 * Виконує перевірку підпису запита.
 *
 * @param ocspreq запит
 * @param adapter адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ocspreq_verify(const OCSPRequest_t *ocspreq, const VerifyAdapter *adapter);

#ifdef __cplusplus
}
#endif

#endif
