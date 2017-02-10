/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_CERTIFICATION_REQUEST_H
#define CRYPTONITE_PKI_API_CERTIFICATION_REQUEST_H

#include "pkix_structs.h"
#include "sign_adapter.h"
#include "verify_adapter.h"
#include "oids.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT CertificationRequest_t *creq_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param creq об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void creq_free(CertificationRequest_t *creq);

/**
 * Ініціалізує запит сертифіката з заданим підписом.
 *
 * @param creq запит сертифіката
 * @param info інформація на запит сертифіката
 * @param aid ідентифікатор алгоритму підпису
 * @param sign значення підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_init_by_sign(CertificationRequest_t *creq, const CertificationRequestInfo_t *info,
        const AlgorithmIdentifier_t *aid, const BIT_STRING_t *sign);

/**
 * Ініціалізує запит сертифіката з обчисленням підпису.
 *
 * @param creq запит сертифіката
 * @param info інформація на запит сертифіката
 * @param adapter адаптер генерації підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_init_by_adapter(CertificationRequest_t *creq, const CertificationRequestInfo_t *info,
        const SignAdapter *adapter);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять повинна бути вивільнена.
 *
 * @param creq запит сертифіката
 * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_encode(const CertificationRequest_t *creq, ByteArray **out);

/**
 * Ініціалізує запит сертифіката з DER-представлення.
 *
 * @param creq запит сертифіката
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_decode(CertificationRequest_t *creq, const ByteArray *in);

/**
 * Повертає об'єкт інформації запиту сертифіката.
 * Виділена пам'ять повинна бути вивільнена.
 *
 * @param creq запит сертифіката
 * @param info об'єкт інформації запиту сертифіката, який створюється
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_get_info(const CertificationRequest_t *creq, CertificationRequestInfo_t **info);

/**
 * Повертає ідентифікатор алгоритму підпису під запитом сертифіката.
 * Виділена пам'ять повинна бути вивільнена.
 *
 * @param creq запит сертифіката
 * @param aid  об'єкт ідентифікатора алгоритма, який створюється
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_get_aid(const CertificationRequest_t *creq, AlgorithmIdentifier_t **aid);

/**
 * Повертає значення підпису запиту сертифіката.
 * Виділена пам'ять повинна бути вивільнена.
 *
 * @param creq запит сертифіката
 * @param sign об'єкт підпису запиту сертифіката, який створюєтья
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_get_sign(const CertificationRequest_t *creq, BIT_STRING_t **sign);

/**
 * Верифікує підпис запиту сертифіката.
 *
 * @param creq запит сертифіката
 * @param adapter адаптер для перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_verify(const CertificationRequest_t *creq, VerifyAdapter *adapter);

CRYPTONITE_EXPORT int creq_get_attributes(const CertificationRequest_t *req, Attributes_t **ext);

/**
 * Створює розширення атрибутів.
 *
 * @param req запит сертифікату
 * @param oid_numbers oid
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int creq_get_ext_by_oid(const CertificationRequest_t *req, const OidNumbers *oid_numbers,
        Extension_t **ext);

#ifdef __cplusplus
}
#endif

#endif
