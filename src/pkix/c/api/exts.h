/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __EXTS_H__
#define __EXTS_H__

#include <stdbool.h>
#include <time.h>

#include "pkix_structs.h"
#include "oids.h"
#include "digest_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює порожній список розширень.
 *
 * @return порожній список розширень
 */
CRYPTONITE_EXPORT Extensions_t *exts_alloc(void);

/**
 * Додає розширення в список розширень.
 *
 * @param exts список розширень
 * @param ext розширення, яке додається
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int exts_add_extension(Extensions_t *exts, const Extension_t *ext);

/**
 * Отримує розширення по заданому oid.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param exts вказівник на список розширень
 * @param oid oid-структура
 * @param ext шукане розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int exts_get_ext_by_oid(const Extensions_t *exts, const OidNumbers *oid, Extension_t **ext);

/**
 * Отримує вказівник на значення шуканого розширення по заданому oid.
 *
 * @param exts вказівник на список розширень
 * @param oid oid-структура
 * @param value значення розширення по заданому oid або NULL
 *
 * @return код помилки або RET_EXT_NOT_FOUND, якщо шукане розширення не знайдено
 */
CRYPTONITE_EXPORT int exts_get_ext_value_by_oid(const Extensions_t *exts, const OidNumbers *oid, ByteArray **value);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param exts об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void exts_free(Extensions_t *exts);

#ifdef __cplusplus
}
#endif

#endif
