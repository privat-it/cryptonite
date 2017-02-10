/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_SIGNER_INFO_H
#define CRYPTONITE_PKI_API_SIGNER_INFO_H

#include "pkix_structs.h"
#include "digest_adapter.h"
#include "verify_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CADES_BES_FORMAT  (1 << 0)
#define CADES_EPES_FORMAT (1 << 1)
#define CADES_C_FORMAT    (1 << 2)
#define CADES_X_FORMAT    (1 << 3)

/**
 * Створює неініціалізований об'єкт SignInfo.
 *
 * @return вказівник на створений контейнер підпису або NULL у випадку помилки
 */
CRYPTONITE_EXPORT SignerInfo_t *sinfo_alloc(void);

/**
 * Вивільняє пам'ять, яку займає SignInfo.
 *
 * @param sinfo об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void sinfo_free(SignerInfo_t *sinfo);

/**
 * Ініціалізує SignerInfo на основі готових даних.
 *
 * @param sinfo             інформація про підписчика
 * @param version           версія контейнера
 * @param signer_id         ідентифікатор SignerInfo
 * @param digest_aid        ідентифікатор алгоритму геша
 * @param signed_attrs      підписані атрибути
 * @param signed_aid        алгоритм підпису
 * @param sign              підпис
 * @param unsigned_attrs    непідписані атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_init(SignerInfo_t *sinfo, int version, const SignerIdentifier_t *signer_id,
        const DigestAlgorithmIdentifier_t *digest_aid, const Attributes_t *signed_attrs,
        const SignatureAlgorithmIdentifier_t *signed_aid, const OCTET_STRING_t *sign,
        const Attributes_t *unsigned_attrs);

/**
 * Повертає байтове представлення об'єкта sinfo в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo об'єкт
 * @param out   вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_encode(const SignerInfo_t *sinfo, ByteArray **out);

/**
 * Ініціалізує об'єкт sinfo з DER-представлення.
 *
 * @param sinfo об'єкт
 * @param in    буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_decode(SignerInfo_t *sinfo, const ByteArray *in);

/**
 * Повертає версію SignInfo.
 *
 * @param sinfo   інформація про підписчика
 * @param version версія
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_version(const SignerInfo_t *sinfo, int *version);

/**
 * Повертає ідентифікатор SignerInfo.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param sid   ідентифікатор SignerInfo
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_signer_id(const SignerInfo_t *sinfo, SignerIdentifier_t **sid);

/**
 * Повертає атрибути, які підписуються.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param attrs атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_signed_attrs(const SignerInfo_t *sinfo, Attributes_t **attrs);

/**
 * Повертає по індексу атрибут, який підписується.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param index індекс
 * @param attr атрибут або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_signed_attr_by_idx(const SignerInfo_t *sinfo, int index, Attribute_t **attr);

/**
 * Повертає по ідентифікатору атрибут, який підписується.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param oid   ідентифікатор
 * @param attr  атрибут
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_signed_attr_by_oid(const SignerInfo_t *sinfo, const OBJECT_IDENTIFIER_t *oid,
        Attribute_t **attr);

/**
 * Повертає прапорець наявності атрибутів, які підписуються.
 *
 * @param sinfo     інформація про підписчика
 * @param flag прапорець наявності атрибутів, які підписуються
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_has_signed_attrs(const SignerInfo_t *sinfo, bool *flag);

/**
 * Повертає атрибути, які не підписуються.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param attrs атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_unsigned_attrs(const SignerInfo_t *sinfo, Attributes_t **attrs);

/**
 * Повертає по індексу атрибут, який не підписується.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo інформація про підписчика
 * @param index індекс
 * @param attr  атрибут або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_unsigned_attr_by_idx(const SignerInfo_t *sinfo, int index, Attribute_t **attr);

/**
 * Повертає по ідентифікатору атрибут, який не підписується.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param sinfo     інформація про підписчика
 * @param oid       ідентифікатор
 * @param attr атрибут
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_unsigned_attr_by_oid(const SignerInfo_t *sinfo, const OBJECT_IDENTIFIER_t *oid,
        Attribute_t **attr);

/**
 * Додає атрибут, який не підписується.
 *
 * @param sinfo інформація про підписчика
 * @param attr  атрибут
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_add_unsigned_attr(SignerInfo_t *sinfo, const Attribute_t *attr);

/**
 * Повертає прапорець наявності атрибутів, які не підписуються.
 *
 * @param sinfo інформація про підписчика
 * @param flag  прапорець наявності атрибутів, які не підписуються
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_has_unsigned_attrs(const SignerInfo_t *sinfo, bool *flag);

/**
 * Виконує перевірку наявності та значення атрибута SigningCertificateV2, який підписується.
 * Згідно з вимогами до формату даних, які підписуються, за п.4.6 и п. 5.3.1 адаптери
 * гешування даних з EncapsulatedContentInfo та обчислення SigningCertificateV2
 * повинні бути налаштовані на ДКЕ №1.
 *
 * @param sinfo інформація про підписчика
 * @param adapter адаптер гешування (для України на ДКЕ №1)
 * @param issuer_cert сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_verify_signing_cert_v2(const SignerInfo_t *sinfo, const DigestAdapter *adapter,
        const Certificate_t *issuer_cert);

/**
 * Виконує перевірку контейнера без перевірки відповідності даних.
 *
 * @param sinfo інформація про підписчика
 * @param da    адаптер обчислення геша
 * @param va    адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int verify_core_without_data(const SignerInfo_t *sinfo, const DigestAdapter *da,
        const VerifyAdapter *va);

CRYPTONITE_EXPORT int sinfo_get_message_digest(const SignerInfo_t *sinfo, ByteArray **hash);

/**
 * Виконує перевірку контейнера.
 *
 * @param sinfo інформація про підписчика
 * @param da    адаптер обчислення геша
 * @param va    адаптер перевірки підпису
 * @param data  дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int verify_core(const SignerInfo_t *sinfo, const DigestAdapter *da, const VerifyAdapter *va,
        const ByteArray *data);

/**
 * Виконує перевірку контейнера без перевірки відповідності даних.
 *
 * @param sinfo інформація про підписчика
 * @param da    адаптер обчислення геша від даних (для України на ДКЕ №1)
 * @param va    адаптер перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_verify_without_data(const SignerInfo_t *sinfo, const DigestAdapter *da,
        const VerifyAdapter *va);

/**
 * Виконує перевірку контейнера.
 *
 * @param sinfo інформація про підписчика
 * @param da    адаптер обчислення геша від даних (для України на ДКЕ №1)
 * @param va    адаптер перевірки підпису
 * @param data  дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_verify(const SignerInfo_t *sinfo, const DigestAdapter *da, const VerifyAdapter *va,
        const ByteArray *data);

/**
 * Повертає відповідність набора атрибутів форматам підпису.
 *
 * @param sinfo інформація про підписчика
 * @param format список атрибутів, які підтримуються
 *               0-й біт - CADES_BES_FORMAT
 *               1-й біт - CADES_EPES_FORMAT
 *               2-й біт - CADES_C_FORMAT
 *               3-й біт - CADES_X_FORMAT
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sinfo_get_format(const SignerInfo_t *sinfo, int *format);

#ifdef __cplusplus
}
#endif

#endif
