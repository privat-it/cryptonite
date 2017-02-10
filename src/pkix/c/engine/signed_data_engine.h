/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SIGNED_DATA_ENGINE_H
#define SIGNED_DATA_ENGINE_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "digest_adapter.h"
#include "sign_adapter.h"
#include "signer_info_engine.h"
#include "oids.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_signed_datda_engine Генератор контейнера підписів
 * @{
 */

typedef struct SignedDataEngine_st SignedDataEngine;

/**
 * Ініціалізує контекст .
 *
 * @param signer вказівник на об'єкт з інформацією про підписчика,
 *               переходить під управління signed_data_engine
 * @param ctx вказівник на створюваний контекст
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_alloc(SignerInfoEngine *signer, SignedDataEngine **ctx);

/**
 * Очищує контекст.
 *
 * @param ctx контекст
 */
CRYPTONITE_EXPORT void esigned_data_free(SignedDataEngine *ctx);

/**
 * Встановлює дані для підписування.
 *
 * @param ctx контекст
 * @param oid ідентифікатор даних
 * @param data дані для підписування
 * @param is_internal_data ознака наявності даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_set_data(SignedDataEngine *ctx, const OidNumbers *oid, const ByteArray *data,
                                            bool is_internal_data);

/**
 * Встановлює геш від даних для підписування.
 *
 * @param ctx контекст
 * @param oid ідентифікатор даних
 * @param hash геш від даних для підписування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_set_hash_data(SignedDataEngine *ctx, const OidNumbers *oid, const ByteArray *hash);

/**
 * Встановлює дані для підписування.
 *
 * @param ctx контекст
 * @param info дані для підписування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_set_content_info(SignedDataEngine *ctx, const EncapsulatedContentInfo_t *info);

/**
 * Встановлює сертифікат підписчика.
 *
 * @param ctx контекст
 * @param cert сертифікат
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_add_cert(SignedDataEngine *ctx, const Certificate_t *cert);

/**
 * Доповнює список відкликаних сертифікатів.
 *
 * @param ctx контекст
 * @param crl СRL список
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_add_crl(SignedDataEngine *ctx, const CertificateList_t *crl);

/**
 * Доповнює інформацію про підписчика.
 *
 * @param ctx контекст
 * @param signer вказівник на об'єкт з інформацією про підписчика,
 *        переходить под управління signed_data_engine
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_add_signer(SignedDataEngine *ctx, SignerInfoEngine *signer);

/**
 * Створює контейнер підписаних даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param ctx контекст
 * @param sdata вказівник на створюваний контейнер підписаних даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int esigned_data_generate(const SignedDataEngine *ctx, SignedData_t **sdata);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
