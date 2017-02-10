/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_ENVELOPED_DATA_H
#define CRYPTONITE_PKI_API_ENVELOPED_DATA_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "cipher_adapter.h"
#include "dh_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований контейнер.
 *
 * @return вказівник на створений контейнер підпису або NULL у випадку помилки
 */
CRYPTONITE_EXPORT EnvelopedData_t *env_data_alloc(void);

/**
 * Вивільняє пам'ять, яку займає контейнер.
 *
 * @param env_data контейнер підпису, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void env_data_free(EnvelopedData_t *env_data);

/**
 * Ініціалізує контейнер на основі готових даних.
 *
 * @param env_data   буфер для контейнера
 * @param version    версія контейнера
 * @param originator інформація про автора
 * @param recipient  інформація про отримувача
 * @param content    контент, який шифрується
 * @param attrs      атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_init(EnvelopedData_t *env_data, const CMSVersion_t *version,
        const OriginatorInfo_t *originator, const RecipientInfos_t *recipient, const EncryptedContentInfo_t *content,
        const UnprotectedAttributes_t *attrs);

/**
 * Повертає байтове представлення контейнера в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param env_data контейнер
 * @param out      вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_encode(const EnvelopedData_t *env_data, ByteArray **out);

/**
 * Ініціалізує контейнер з DER-представлення.
 *
 * @param env_data контейнер
 * @param in       буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_decode(EnvelopedData_t *env_data, const ByteArray *in);

/**
 * Перевіряє наявність сертифіката автора контейнера.
 *
 * @param env_data контейнер
 * @param flag     прапорець наявності сертифіката
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_has_originator_cert(const EnvelopedData_t *env_data, bool *flag);

/**
 * Повертає сертифікат автора контейнера.
 *
 * @param env_data        контейнер
 * @param originator_cert сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_get_originator_cert(const EnvelopedData_t *env_data, Certificate_t **originator_cert);

/**
 * Повертає відкритий ключ автора контейнера.
 *
 * @param env_data           контейнер
 * @param originator_cert    сертифікат
 * @param originator_pub_key відкритий ключ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_data_get_originator_public_key(const EnvelopedData_t *env_data,
        const Certificate_t *originator_cert, ByteArray **originator_pub_key);

/**
 * Повертає ідентифікатор алгоритму шифрування контейнера.
 *
 * @param env_data контейнер
 * @param encr_aid ідентифікатор алгоритму
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_get_content_encryption_aid(const EnvelopedData_t *env_data, AlgorithmIdentifier_t **encr_aid);

/**
 * Повертає розшифрований вміст контейнера.
 *
 * @param env_data контейнер
 * @param ca       адаптер шифрування
 * @param key      ключ шифрування
 * @param out      буфер вмісту контейнера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int env_decrypt_data(const EnvelopedData_t *env_data, const ByteArray *enc_data_opt,
        const Certificate_t *originator_cert_opt, const DhAdapter *recipient_dha, const Certificate_t *recipient_cert,
        ByteArray **out);

#ifdef __cplusplus
}
#endif

#endif
