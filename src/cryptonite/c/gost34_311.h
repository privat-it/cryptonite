/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_GOST34311_H
#define CRYPTONITE_GOST34311_H

#include "byte_array.h"
#include "gost28147.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГОСТ 34.311
 */
typedef struct Gost34311Ctx_st Gost34311Ctx;

/**
 * Створює контекст ГОСТ 34.311 зі стандартним sbox.
 *
 * @param sbox_id ідентифікатор стандартной таблиці замін
 * @param sync синхропосилка
 * @return контекст ГОСТ 34.311
 */
CRYPTONITE_EXPORT Gost34311Ctx *gost34_311_alloc(Gost28147SboxId sbox_id, const ByteArray *sync);

/**
 * Створює контекст ГОСТ 34.311 з користувацьким sbox.
 *
 * @param sbox користувацький sbox
 * @param sync синхропосилка
 * @return контекст ГОСТ 34.311
 */
CRYPTONITE_EXPORT Gost34311Ctx *gost34_311_alloc_user_sbox(const ByteArray *sbox, const ByteArray *sync);

CRYPTONITE_EXPORT Gost34311Ctx *gost34_311_copy_with_alloc(const Gost34311Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param data дані для шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost34_311_update(Gost34311Ctx *ctx, const ByteArray *data);

/**
 * Завершує вироботку геша і повертає його значення.
 *
 * @param ctx контекст ГОСТ 34.311
 * @param hash геш вектор
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost34_311_final(Gost34311Ctx *ctx, ByteArray **hash);

/**
 * Звільняє контекст ГОСТ 34.311.
 *
 * @param ctx контекст ГОСТ 34.311
 */
CRYPTONITE_EXPORT void gost34_311_free(Gost34311Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
