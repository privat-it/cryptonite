/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_CERT_H
#define CRYPTONITE_PKI_API_CERT_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "sign_adapter.h"
#include "verify_adapter.h"
#include "oids.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізоіваний об'єкт у випадку помилки.
 *
 * @return вказівник на створений об'єкт або NULL
 */
CRYPTONITE_EXPORT Certificate_t *cert_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param cert об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void cert_free(Certificate_t *cert);

/**
 * Ініціалізує сертифікат на основі готових даних.
 *
 * @param cert сертифікат
 * @param tbs_cert інформація сертификата
 * @param aid алгоритм підпису
 * @param sign значення підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_init_by_sign(Certificate_t *cert, const TBSCertificate_t *tbs_cert,
        const AlgorithmIdentifier_t *aid, const BIT_STRING_t *sign);

/**
 * Ініціалізує сертифікат з обчисленням підпису.
 *
 * @param cert сертифікат
 * @param tbs_cert інформація сертификата
 * @param adapter адаптер виробки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_init_by_adapter(Certificate_t *cert, const TBSCertificate_t *tbs_cert,
        const SignAdapter *adapter);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_encode(const Certificate_t *cert, ByteArray **out);

/**
 * Ініціалізує сертифікат з DER-представлення
 *
 * @param cert сертифікат
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_decode(Certificate_t *cert, const ByteArray *in);

/**
 * Повертає наявність обов'язкових доповнень сертифіката, які не підтримуються.
 *
 * @param cert сертифікат
 * @param flag наявність доповнень, які не підтримуються
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_has_unsupported_critical_ext(const Certificate_t *cert, bool *flag);

/**
 * Отримує перелік ідентифікаторів обов'язкових доповнень сертифіката.
 *
 * @param cert сертифікат
 * @param oids перелік ідентифікаторів або NULL
 * @param cnt кількість ідентифікаторів або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_critical_ext_oids(const Certificate_t *cert, OBJECT_IDENTIFIER_t ***oids, size_t *cnt);

/**
 * Отримує перелік ідентифікаторів необов'язкових доповнень сертифіката.
 *
 * @param cert сертифікат
 * @param oids перелік ідентифікаторів або NULL
 * @param cnt кількість ідентифікаторів або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_non_critical_ext_oids(const Certificate_t *cert, OBJECT_IDENTIFIER_t ***oids,
        size_t *cnt);

/**
 * Отримує байтове представлення доповнення по ідентифікатору.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param oid_numbers ідентифікатор
 * @param out вказівник на пам'ять, що виділяється
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_ext_value(const Certificate_t *cert, const OidNumbers *oid_numbers, ByteArray **out);

/**
 * Перевіряє валідність сертифікату на поточний момент часу.
 *
 * @param cert сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_check_validity(const Certificate_t *cert);

/**
 * Перевіряє валідність сертифікату на заданий момент часу.
 *
 * @param cert сертифікат
 * @param date дата для валідації
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_check_validity_with_date(const Certificate_t *cert, time_t date);

/**
 * Повертає версію сертифіката.
 *
 * @param cert сертифікат
 * @param version версія сертифіката
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_version(const Certificate_t *cert, long *version);

/**
 * Повертає 20 байтний серійний номер сертифіката.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param sn  вказівник на буфер для серійного номера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_sn(const Certificate_t *cert, ByteArray **sn);

/**
 * Повертає дату початку дії сертифіката.
 *
 * @param cert сертифікат
 * @param date дата почтаку дії сертифіката
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_not_before(const Certificate_t *cert, time_t *date);

/**
 * Повертає дату закінчення дії сертифіката.
 *
 * @param cert сертифікат
 * @param date дата закінчення дії сертифіката
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_not_after(const Certificate_t *cert, time_t *date);

/**
 * Повертає інформацію про сертифікат.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param tbs_cert інформація про сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_tbs_cert(const Certificate_t *cert, TBSCertificate_t **tbs_cert);

/**
 * Повертає байтове представлення в DER-кодуванні інформації про сертифікат.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_tbs_info(const Certificate_t *cert, ByteArray **out);

/**
 * Повертає ідентифікатор алгоритму виробки підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param aid ідентифікатор алгоритму виробки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_aid(const Certificate_t *cert, AlgorithmIdentifier_t **aid);

/**
 * Повертає байтове представлення в DER-кодуванні ЕЦП.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param sign вказівник на BIT_STRING, який містить ЕЦП.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_sign(const Certificate_t *cert, BIT_STRING_t **sign);

/**
 * Повертає атрибути доступу ключа.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param attr атрибути доступу ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_key_usage(const Certificate_t *cert, KeyUsage_t **attr);

/**
 * Повертає кількість проміжних сертифікатів.
 *
 * @param cert сертифікат
 * @param cnt кількість проміжних сертифікатів, -1 якщо їх немає
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_basic_constrains(const Certificate_t *cert, int *cnt);

/**
 * Перевіряє, чи належить даний сертифікат OCSP серверу.
 * Сертифікат OCSP сервера  повинен мати розширення ExtendedKeyUsage,
 * в якому міститься єдиний OID 1.3.6.1.5.5.7.3.9.
 *
 * @param cert сертифікат
 * @param flag true - якщо сертифікат належить OCSP серверу
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_is_ocsp_cert(const Certificate_t *cert, bool *flag);

/**
 * Виконує перевірку сертифіката.
 *
 * @param cert сертифікат
 * @param adapter адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_verify(const Certificate_t *cert, const VerifyAdapter *adapter);

/**
 * Повертає SubjectPublicKeyInfo.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cert сертифікат
 * @param spki вказівник на структуру SubjectPublicKeyInfo
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cert_get_spki(const Certificate_t *cert, SubjectPublicKeyInfo_t **spki);

CRYPTONITE_EXPORT bool cert_check_sid(const Certificate_t *certificate, const SignerIdentifier_t *sid);

CRYPTONITE_EXPORT int cert_get_subj_key_id(const Certificate_t *cert, ByteArray **subj_key_id);

CRYPTONITE_EXPORT int cert_get_auth_key_id(const Certificate_t *cert, ByteArray **auth_key_id);

CRYPTONITE_EXPORT int cert_get_qc_statement_limit(const Certificate_t *cert, char **currency_code, long *amount,
        long *exponent);

CRYPTONITE_EXPORT bool cert_check_validity_encode(const ByteArray *cert);

CRYPTONITE_EXPORT int cert_check_pubkey_and_usage(const Certificate_t *cert, const ByteArray *pub_key, int key_usage,
        bool *flag);

CRYPTONITE_EXPORT int cert_get_tsp_url(const Certificate_t *cert, ByteArray **data);

#ifdef __cplusplus
}
#endif

#endif
