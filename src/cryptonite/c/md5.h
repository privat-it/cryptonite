/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_MD5_H
#define CRYPTONITE_MD5_H

#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст MD5.
 */
typedef struct MD5Ctx_st Md5Ctx;

/**
 * Створює контекст MD5.
 *
 * @return контекст MD5
 */
CRYPTONITE_EXPORT Md5Ctx *md5_alloc(void);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст MD5
 * @param data фрагмент даних
 * @return код помилки
 */
CRYPTONITE_EXPORT int md5_update(Md5Ctx *ctx, const ByteArray *data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст MD5
 * @param hash геш-вектор
 * @return код помилки
 */
CRYPTONITE_EXPORT int md5_final(Md5Ctx *ctx, ByteArray **hash);

/**
 * Звільняє контекст MD5.
 *
 * @param ctx контекст MD5
 */
CRYPTONITE_EXPORT void md5_free(Md5Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
