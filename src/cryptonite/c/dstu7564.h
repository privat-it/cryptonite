/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU7564_H
#define CRYPTONITE_DSTU7564_H

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct Dstu7564Ctx_st Dstu7564Ctx;

typedef enum {
    DSTU7564_SBOX_1 = 0 /*sbox із стандарту*/
} Dstu7564SboxId;

/**
 * Створює контекст ДСТУ 7564 зі стандартною таблицею замін.
 *
 * @param sbox_id ідентифікатор стандартної таблиці замін
 * @return контекст ДСТУ 7564
 */
CRYPTONITE_EXPORT Dstu7564Ctx *dstu7564_alloc(const Dstu7564SboxId sbox_id);

/**
 * Створює контекст ДСТУ 7564 з користувацьким sbox.
 *
 * @param sbox користувацька таблиця замін розміром 1024 байт
 * @return контекст ДСТУ 7564
 */
CRYPTONITE_EXPORT Dstu7564Ctx *dstu7564_alloc_user_sbox(const ByteArray *sbox);

/**
 * Ініціалізація контексту DSTU7564.
 *
 * @param ctx контекст ДСТУ 7564
 * @param hash_len байтовий розмір геша, значення у межі 1..64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_init(Dstu7564Ctx *ctx, size_t hash_len);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ДСТУ 7564
 * @param data дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_update(Dstu7564Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ДСТУ 7564
 * @param hash геш від даних
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_final(Dstu7564Ctx *ctx, ByteArray **hash);

/**
 * Ініціалізує контекст ДСТУ 7564 для створення кода аутентификації.
 *
 * @param ctx контекст ДСТУ 7564
 * @param key ключ аутентификации для режиму kmac
 * @param mac_len розмір імітовставки (байт), значення 32, 48, 64
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_init_kmac(Dstu7564Ctx *ctx, const ByteArray *key, size_t mac_len);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ДСТУ 7564
 * @param data дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_update_kmac(Dstu7564Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ДСТУ 7564
 * @param mac код аутентификации
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7564_final_kmac(Dstu7564Ctx *ctx, ByteArray **mac);

/**
 * Звільняє контекст ДСТУ 7564.
 *
 * @param ctx контекст ДСТУ 7564
 */
CRYPTONITE_EXPORT void dstu7564_free(Dstu7564Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
