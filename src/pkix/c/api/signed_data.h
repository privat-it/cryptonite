/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_SIGNED_DATA_H
#define CRYPTONITE_PKI_API_SIGNED_DATA_H

#include "pkix_structs.h"
#include "verify_adapter.h"
#include "sign_adapter.h"
#include "digest_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum TspStatus_st {
    TSP_NONE = 0,
    TSP_VALID = 1,
    TSP_NO_CERT_FOR_VERIFY = 2,
    TSP_INVALID_DATA = 3,
    TSP_INVALID = 4
} TspStatus;

/**
 * Створює неініціалізований контейнер підпису.
 *
 * @return вказівник на створений контейнер підпису або NULL у випадку помилки
 */
CRYPTONITE_EXPORT SignedData_t *sdata_alloc(void);

/**
 * Вивільняє пам'ять, яку займає контейнер підпису.
 *
 * @param sdata контейнер підпису, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void sdata_free(SignedData_t *sdata);

/**
 * Ініціалізує контейнер підпису на основі готових даних.
 *
 * @param sdata        контейнер підпису
 * @param version      версія контейнера
 * @param digest_aid   алгоритми виробки геша від даних, які підписуються
 * @param content      контент, який підписується
 * @param signer       інформація про підписчиків
 */
CRYPTONITE_EXPORT int sdata_init(SignedData_t *sdata, int version, const DigestAlgorithmIdentifiers_t *digest_aid,
        const EncapsulatedContentInfo_t *content, const SignerInfos_t *signer);

/**
 * Повертає байтове представлення контейнера підпису в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param out   вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_encode(const SignedData_t *sdata, ByteArray **out);

/**
 *Ініціалізує контейнер підпису з DER-представлення.
 *
 * @param sdata контейнер підпису
 * @param in    буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_decode(SignedData_t *sdata, const ByteArray *in);

/**
 * Повертає версію контейнера підпису.
 *
 * @param sdata   контейнер підпису
 * @param version версія контейнера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_version(const SignedData_t *sdata, int *version);

/**
 * Встановлює версію контейнера підпису.
 *
 * @param sdata   контейнер підпису
 * @param version версія контейнера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_version(SignedData_t *sdata, int version);

/**
 * Повертає ідентифікатор алгоритму виробки підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param digest_aids ідентифікатор алгоритму виробки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_digest_aids(const SignedData_t *sdata, DigestAlgorithmIdentifiers_t **digest_aids);

/**
 * Встановлює ідентифікатор алгоритму виробки підпису.
 *
 * @param sdata   контейнер підпису
 * @param digest_aids ідентифікатор алгоритму виробки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_digest_aids(SignedData_t *sdata, const DigestAlgorithmIdentifiers_t *digest_aids);

/**
 * Повертає ідентифікатор алгоритму виробки підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param index індекс
 * @param digest_aid ідентифікатор алгоритму виробки підпису або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_digest_aid_by_idx(const SignedData_t *sdata, int index,
        AlgorithmIdentifier_t **digest_aid);

/**
 * Повертає контент, який підписується.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata   контейнер підпису
 * @param content створюваний об'єкт контейнера даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_content(const SignedData_t *sdata, EncapsulatedContentInfo_t **content);

/**
 * Встановлює контент, який підписується.
 *
 * @param sdata   контейнер підпису
 * @param content контент
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_content(SignedData_t *sdata, const EncapsulatedContentInfo_t *content);

/**
 * Повертає дані.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param data  створюваний об'єкт підписаних даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_data(const SignedData_t *sdata, ByteArray **data);

/**
 * Повертає мітку часу.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param info  створюваний об'єкт підписаних даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_tst_info(const SignedData_t *sdata, TSTInfo_t **info);

/**
 * Повертає множину сертифікатів для перевірки підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param certs сертифікати для перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_certs(const SignedData_t *sdata, CertificateSet_t **certs);

/**
 * Встановлює сертифікати для перевірки підпису.
 *
 * @param sdata контейнер підпису
 * @param certs сертифікати для перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_certs(SignedData_t *sdata, const CertificateSet_t *certs);

/**
 * Повертає прапорець наявності сертифікатов для перевірки підпису.
 *
 * @param sdata контейнер даних
 * @param flag  флаг наявності сертифікатов в контейнері
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_has_certs(const SignedData_t *sdata, bool *flag);

/**
 * Повертає списки відкликаних сертифікатів для перевірки статусу сертифікатів.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param crls  списки відкликаних сертифікатов
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_crls(const SignedData_t *sdata, RevocationInfoChoices_t **crls);

/**
 * Встановлює списки відкликаних сертифікатів для перевірки статусу сертифікатів.
 *
 * @param sdata контейнер підпису
 * @param crls списки відкликаних сертифікатів
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_crls(SignedData_t *sdata, const RevocationInfoChoices_t *crls);

/**
 * Повертає прапорець наявності відкликаних сертифікатів в контейнері.
 *
 * @param sdata контейнер даних
 * @param flag  прапорець наявності CRL в контейнері
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_has_crls(const SignedData_t *sdata, bool *flag);

/**
 * Повертає інформацію про підписчиків.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata  контейнер підпису
 * @param sinfos інформація про підписчиків
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_signer_infos(const SignedData_t *sdata, SignerInfos_t **sinfos);

/**
 * Встановлює інформацію про підписчиків.
 *
 * @param sdata  контейнер підпису
 * @param sinfos інформація про підписчиків
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_set_signer_infos(SignedData_t *sdata, const SignerInfos_t *sinfos);

/**
 * Повертає по індексу сертифікат для перевірки підпису.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param index індекс
 * @param cert  сертифікат або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_cert_by_idx(const SignedData_t *sdata, int index, CertificateChoices_t **cert);

/**
 * Повертає по індексу відкликаний сертифікат.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param index індекс
 * @param crl   відкликаний сертифікат або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_crl_by_idx(const SignedData_t *sdata, int index, RevocationInfoChoice_t **crl);

/**
 * Повертає по індексу інформацію про підписника.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sdata контейнер підпису
 * @param index індекс
 * @param sinfo інформація о подписчике або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_get_signer_info_by_idx(const SignedData_t *sdata, int index, SignerInfo_t **sinfo);

/**
 * Виконує перевірку контейнера без даних.
 *
 * @param sdata контейнер підпису
 * @param da    адаптер обчислення геша
 * @param va    адаптер перевірки підпису
 * @param index індекс
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_verify_without_data_by_adapter(const SignedData_t *sdata, const DigestAdapter *da,
        const VerifyAdapter *va, int index);

CRYPTONITE_EXPORT int sdata_get_content_time_stamp(const SignedData_t *sdata, int index, TspStatus *status,
        time_t *content_time_stamp, SignerIdentifier_t **signer_identifier);

CRYPTONITE_EXPORT int sdata_get_signing_time(const SignedData_t *sdata, int index, time_t *signing_time);

/**
 * Виконує перевірку контейнера.
 *
 * @param sdata контейнер підпису
 * @param da    адаптер обчислення геша
 * @param va    адаптер перевірки підпису
 * @param data  дані
 * @param index індекс
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_verify_external_data_by_adapter(const SignedData_t *sdata, const DigestAdapter *da,
        const VerifyAdapter *va, const ByteArray *data, int index);

/**
 * Виконує перевірку контейнера внутрішніх даних.
 *
 * @param sdata контейнер підпису
 * @param da    адаптери обчислення геша
 * @param va    адаптери перевірки підпису
 * @param index індекс
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_verify_internal_data_by_adapter(const SignedData_t *sdata, const DigestAdapter *da,
        const VerifyAdapter *va, int index);

/**
 * Виконує перевірку атрибуту SigningCerificateV2.
 *
 * @param sdata контейнер підпису
 * @param da адаптер обчислення геша
 * @param cert сертифікат
 * @param index індекс підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sdata_verify_signing_cert_by_adapter(const SignedData_t *sdata, const DigestAdapter *da,
        const Certificate_t *cert, int index);

#ifdef __cplusplus
}
#endif

#endif
