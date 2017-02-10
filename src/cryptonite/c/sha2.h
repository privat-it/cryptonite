/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_SHA2_H
#define CRYPTONITE_SHA2_H

#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Контекст SHA2.
 */
typedef struct Sha2Ctx_st Sha2Ctx;

typedef enum {
    SHA2_VARIANT_224 = 0,
    SHA2_VARIANT_256 = 1,
    SHA2_VARIANT_384 = 2,
    SHA2_VARIANT_512 = 3
} Sha2Variant;

/**
 * Створює контекст SHA2.
 *
 * @return контекст SHA2
 */
CRYPTONITE_EXPORT Sha2Ctx *sha2_alloc(Sha2Variant variant);

CRYPTONITE_EXPORT Sha2Ctx *sha2_copy_with_alloc(const Sha2Ctx *ctx);

/**
 * Модифікує геш-вектор фрагментом даних.
 *
 * @param ctx контекст SHA2
 * @param data дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int sha2_update(Sha2Ctx *ctx, const ByteArray *data);

/**
 * Завершує обчислення геш-вектора і повертає його значення.
 *
 * @param ctx контекст SHA2
 * @param out геш від даних
 * @return код помилки
 */
CRYPTONITE_EXPORT int sha2_final(Sha2Ctx *ctx, ByteArray **out);

/**
 * Звільняє контекст SHA2.
 *
 * @param ctx контекст SHA2
 */
CRYPTONITE_EXPORT void sha2_free(Sha2Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif

