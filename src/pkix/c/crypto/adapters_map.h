/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTO_ADAPTERS_MAP_H
#define CRYPTONITE_PKI_CRYPTO_ADAPTERS_MAP_H

#include "digest_adapter.h"
#include "sign_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AdaptersMap_st {
    SignAdapter **sign;        /**< Масив адаптерів формування підпису */
    DigestAdapter **digest;    /**< Масив адаптерів виробки геша */
    int count;                    /**< Поточна кількість вказівників в масиві */
} AdaptersMap;

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT AdaptersMap *adapters_map_alloc(void);

/**
 * Очищує контекст adapters_map_t.
 *
 * @param adapters контекст
 */
CRYPTONITE_EXPORT void adapters_map_free(AdaptersMap *adapters);

/**
 * Очищує контекст adapters_map_t не чіпаючи контексты адаптерів.
 *
 * @param adapters контекст
 */
CRYPTONITE_EXPORT void adapters_map_with_const_content_free(AdaptersMap *adapters);

/**
 * Додає адаптери гешування та формування підпису в список адаптерів.
 *
 * @param adapters_map список адаптерів
 * @param digest адаптер гешування
 * @param sign адаптер підписування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int adapters_map_add(AdaptersMap *adapters_map, DigestAdapter *digest, SignAdapter *sign);

#ifdef __cplusplus
}
#endif

#endif
