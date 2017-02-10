/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SIGNER_INFO_ENGINE_H
#define SIGNER_INFO_ENGINE_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "digest_adapter.h"
#include "sign_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_signer_info_engine Генератор контейнера інформації про підписчика
 *
 * Движок генерації SignerInfo.
 * Signer Info містить інформацію про підписчика, використаний ним алгоритм гешування,
 * використаний набір підписуємих та не підписуємих атрибутів, а також алгоритм і
 * значення підпису від атрибутів, які підписуються.
 * @{
 */


/**
 * Контекст генератора контейнеру інформації про підписчика
 */
typedef struct SignerInfoEngine_st SignerInfoEngine;

/**
 * Ініціалізує контекст .
 *
 * @param sa посилання на адаптер обчислення підпису
 * @param ess_da посилання на адаптер гешування для формування атрибуту “ESS signing-certificate v2”
 * @param data_da посилання на адаптер гешування для формування атрибуту “message-digest“
 * @param ctx вказівник на створюваний контекст
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_alloc(const SignAdapter *sa, const DigestAdapter *ess_da,
                                         const DigestAdapter *data_da, SignerInfoEngine **ctx);

/**
 * Очищує контекст.
 *
 * @param ctx контекст
 */
CRYPTONITE_EXPORT void esigner_info_free(SignerInfoEngine *ctx);

/**
 * Визначає формат інформації про підписчика.
 * Визначає , чи додавати при генерації обов'язкові атрибути формату CAdES-BES.
 * За замовчуванням - додавати.
 *
 * @param ctx контекст
 * @param flag використання трьох основних атрибутів/довільний формат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_set_bes_attrs(SignerInfoEngine *ctx, bool flag);

/**
 * Установка підписуємих атрибутів.
 *
 * @param ctx контекст
 * @param signed_attrs атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_set_signed_attrs(SignerInfoEngine *ctx, const Attributes_t *signed_attrs);

/**
 * Додає підписуємий атрибут.
 *
 * @param ctx контекст
 * @param signed_attr атрибут
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_add_signed_attr(SignerInfoEngine *ctx, const Attribute_t *signed_attr);

/**
 * Установка непідписуємих атрибутів.
 *
 * @param ctx контекст
 * @param unsigned_attrs атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_set_unsigned_attrs(SignerInfoEngine *ctx, const Attributes_t *unsigned_attrs);

/**
 * Додає непідписуємий атрибут.
 *
 * @param ctx контекст
 * @param unsigned_attr атрибут
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_add_unsigned_attr(SignerInfoEngine *ctx, const Attribute_t *unsigned_attr);

/**
 * Встановлює дані тип та значення підписуємих даних.
 *
 * @param ctx контекст
 * @param data_type_oid тип даних, які підписуються
 * @param data дані, які підписуються
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_set_data(SignerInfoEngine *ctx, const OBJECT_IDENTIFIER_t *data_type_oid,
                                            const OCTET_STRING_t *data);

/**
 * Встановлює тип та геш від підписуємих даних.
 *
 * @param ctx контекст
 * @param data_type_oid тип підписуємих даних
 * @param hash_data геш від підписуємих даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_set_hash_data(SignerInfoEngine *ctx, const OBJECT_IDENTIFIER_t *data_type_oid,
                                                 const OCTET_STRING_t *hash_data);

/**
 * Генерує інформацію про підписчика.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ctx контекст
 * @param sinfo інформація про підписчика
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigner_info_generate(const SignerInfoEngine *ctx, SignerInfo_t **sinfo);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
