/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_SHA1_H
#define CRYPTONITE_SHA1_H

#include "byte_array.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст SHA1.
 */
typedef struct Sha1Ctx_st Sha1Ctx;

/**
 * Створює контекст SHA1.
 *
 * @return контекст SHA1
 */
CRYPTONITE_EXPORT Sha1Ctx *sha1_alloc(void);

CRYPTONITE_EXPORT Sha1Ctx *sha1_copy_with_alloc(const Sha1Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SHA1
 * @param data дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int sha1_update(Sha1Ctx *ctx, const ByteArray *data);

/**
 * Завершує виробку геша і повертає його значення.
 *
 * @param ctx контекст SHA1
 * @param out геш від даних
 * @return код помилки
 */
CRYPTONITE_EXPORT int sha1_final(Sha1Ctx *ctx, ByteArray **out);

/**
 * Звільняє контекст SHA1.
 *
 * @param ctx контекст SHA1
 */
CRYPTONITE_EXPORT void sha1_free(Sha1Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
