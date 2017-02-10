/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __ENVELOPED_DATA_ENGINE_H__
#define __ENVELOPED_DATA_ENGINE_H__

#include <stdbool.h>

#include "pkix_structs.h"
#include "dh_adapter.h"
#include "cipher_adapter.h"
#include "prng.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_envel_data_engine Генератор контейнеру захищених даних
 * @{
 */

typedef struct EnvelopedDataEngine_st EnvelopedDataEngine;

/**
 * Ініціалізує контекст .
 *
 * @param ctx контекст
 * @param dha посилання на ініціалізований адаптер виробки спільного секрету
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_alloc(const DhAdapter *dha, EnvelopedDataEngine **ctx);

/**
 * Очищує контекст .
 *
 * @param ctx контекст
 */
CRYPTONITE_EXPORT void eenvel_data_free(EnvelopedDataEngine *ctx);

/**
 * Встановлює сертифікат підписчика.
 *
 * @param ctx контекст
 * @param cert сертифікат підписчика
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_set_originator_cert(EnvelopedDataEngine *ctx, const Certificate_t *cert);

/**
 * Встановлює атрибути.
 *
 * @param ctx контекст
 * @param attrs атрибути
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_set_unprotected_attrs(EnvelopedDataEngine *ctx, const UnprotectedAttributes_t *attrs);

/**
 * Встановлює дані для контейнера захищених даних.
 *
 * @param ctx контекст
 * @param oid ідентифікатор даних
 * @param data дані для формування контейнеру
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_set_data(EnvelopedDataEngine *ctx, const OBJECT_IDENTIFIER_t *oid,
                                           const ByteArray *data);

/**
 * Встановлює ідентифікатори алгоритму шифрування.
 *
 * @param ctx контекст
 * @param oid ідентифікатор алгоритму шифрування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_set_encription_oid(EnvelopedDataEngine *ctx, const OBJECT_IDENTIFIER_t *oid);

/**
 * Чи зберігати сертифікати в контейнері?
 *
 * @param ctx контекст
 * @param is_save_cert прапорець зберігання сертифікатів
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_set_save_cert_optional(EnvelopedDataEngine *ctx, bool is_save_cert);

/**
 * Чи зберігати дані в контейнері?
 *
 * @param ctx контекст
 * @param is_save_data прапорець зберігання даних
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int eenvel_data_set_save_data_optional(EnvelopedDataEngine *ctx, bool is_save_data);

/**
 * Встановлює ГПВЧ.
 *
 * @param ctx контекст
 * @param prng ГПВЧ
 *
 * @return код ошибки
 */
CRYPTONITE_EXPORT int eenvel_data_set_prng(EnvelopedDataEngine *ctx, PrngCtx *prng);

/**
 * Дадає ще одного отримувача захищеного контейнеру.
 *
 * @param ctx контекст
 * @param cert сертифікат отримувача
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_add_recipient(EnvelopedDataEngine *ctx, const Certificate_t *cert);

/**
 * Генерація контейнера захищених даних.
 *
 * @param ctx      контекст
 * @param env_data контейнер захищених даних
 * @param enc_data шифровані данні
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int eenvel_data_generate(EnvelopedDataEngine *ctx, EnvelopedData_t **env_data, ByteArray **enc_data);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
