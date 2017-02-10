/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_CRL_H
#define CRYPTONITE_PKI_API_CRL_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "sign_adapter.h"
#include "verify_adapter.h"
#include "TBSCertList.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT CertificateList_t *crl_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param crl об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void crl_free(CertificateList_t *crl);

/**
 * Ініціалізує CRL з заданим підписом.
 *
 * @param crl CRL
 * @param tbs_crl інформація про CRL
 * @param aid ідентифікатор алгоритму підпису
 * @param sign значення підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_init_by_sign(CertificateList_t *crl, const TBSCertList_t *tbs_crl,
        const AlgorithmIdentifier_t *aid, const BIT_STRING_t *sign);

/**
 * Ініціалізує CRL з обчисленням підпису.
 *
 * @param crl CRL
 * @param tbs_crl інформація о CRL
 * @param adapter адаптер генерації підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_init_by_adapter(CertificateList_t *crl, const TBSCertList_t *tbs_crl,
        const SignAdapter *adapter);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_encode(const CertificateList_t *crl, ByteArray **out);

/**
 * Ініціалізує CRL з DER-представлення.
 *
 * @param crl CRL
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_decode(CertificateList_t *crl, const ByteArray *in);

/**
 * Повертає інформацію про CRL.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param tbs_crl створюваний об'єкт інформації про CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_get_tbs(const CertificateList_t *crl, TBSCertList_t **tbs_crl);

/**
 * Встановлює інформацію про CRL.
 *
 * @param crl CRL
 * @param tbs_crl інформація про CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_set_tbs(CertificateList_t *crl, const TBSCertList_t *tbs_crl);

/**
 * Повертає ідентифікатор алгоритму підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param aid створюваний об'єкт алгоритму підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_get_sign_aid(const CertificateList_t *crl, AlgorithmIdentifier_t **aid);

/**
 * Встановлює алгоритм підпису контейнера.
 *
 * @param crl CRL
 * @param aid алгоритм підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_set_sign_aid(CertificateList_t *crl, const AlgorithmIdentifier_t *aid);

/**
 * Повертає значення підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param sign створюваний об'єкт підпису CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_get_sign(const CertificateList_t *crl, BIT_STRING_t **sign);

/**
 * Встановлює алгоритм підпису контейнера.
 *
 * @param crl CRL
 * @param sign підпис CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_set_sign(CertificateList_t *crl, const BIT_STRING_t *sign);

/**
 * Перевіряє, чи наявний даний сертифікат в переліку відкликаних сертифікатов.
 *
 * @param crl CRL
 * @param cert перевіряємий сертифікат
 * @param flag прапорець наявності сертифіката в CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_check_cert(const CertificateList_t *crl, const Certificate_t *cert, bool *flag);

/**
 * Повертає інформацію про відкликаний сертифікат по вихідному сертифікату.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param cert перевіряємий сертифікат
 * @param rc створюваний об'єкт інформації про відкликаний сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_get_cert_info(const CertificateList_t *crl, const Certificate_t *cert,
        RevokedCertificate_t **rc);

/**
 * Повертає інформацію про відкликаний сертифікат по серійному номеру сертифіката.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param crl CRL
 * @param cert_sn серійный номер сертифіката
 * @param rc створюваний об'єкт інформації про відкликаний сертифікат або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_get_cert_info_by_sn(const CertificateList_t *crl, const INTEGER_t *cert_sn,
        RevokedCertificate_t **rc);

/**
 * Перевіряє, чи відноситься даний CRL до повних.
 *
 * @param crl CRL
 * @param flag правпорець приналежності CRL до повних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_is_full(const CertificateList_t *crl, bool *flag);

/**
 * Перевіряє, чи відноситься даний CRL до часткових.
 *
 * @param crl CRL
 * @param flag прапорець приналежності CRL до часткових
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_is_delta(const CertificateList_t *crl, bool *flag);

/**
 * Верифікує підпис CRL.
 *
 * @param crl CRL
 * @param adapter адаптер для перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int crl_verify(const CertificateList_t *crl, const VerifyAdapter *adapter);

CRYPTONITE_EXPORT int crl_get_crl_number(const CertificateList_t *crl, ByteArray **crl_number);

CRYPTONITE_EXPORT int crl_get_distribution_points(const CertificateList_t *crl, char ***url, size_t *url_len);

CRYPTONITE_EXPORT int crl_get_this_update(const CertificateList_t *crl, time_t *this_update);

#ifdef __cplusplus
}
#endif

#endif
