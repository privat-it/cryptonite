/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_GOST28147_H
#define CRYPTONITE_GOST28147_H

#include "byte_array.h"
#include "prng.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст ГОСТ 28147.
 */
typedef struct Gost28147Ctx_st Gost28147Ctx;

/**
 * Ідентифікатори стандартних таблиць замін.
 */
typedef enum {
    GOST28147_SBOX_ID_1 = 1,   /**< Таблиця замін ДКЕ №1 із доповнення 1 до інструкції №114. */
    GOST28147_SBOX_ID_2 = 2,   /**< Таблиця замін ДКЕ №1 із доповнення 2 до інструкції №114. */
    GOST28147_SBOX_ID_3 = 3,   /**< Таблиця замін ДКЕ №1 із доповнення 3 до інструкції №114. */
    GOST28147_SBOX_ID_4 = 4,   /**< Таблиця замін ДКЕ №1 із доповнення 4 до інструкції №114. */
    GOST28147_SBOX_ID_5 = 5,   /**< Таблиця замін ДКЕ №1 із доповнення 5 до інструкції №114. */
    GOST28147_SBOX_ID_6 = 6,   /**< Таблиця замін ДКЕ №1 із доповнення 6 до інструкції №114. */
    GOST28147_SBOX_ID_7 = 7,   /**< Таблиця замін ДКЕ №1 із доповнення 7 до інструкції №114. */
    GOST28147_SBOX_ID_8 = 8,   /**< Таблиця замін ДКЕ №1 із доповнення 8 до інструкції №114. */
    GOST28147_SBOX_ID_9 = 9,   /**< Таблиця замін ДКЕ №1 із доповнення 9 до інструкції №114. */
    GOST28147_SBOX_ID_10 = 10, /**< Таблиця замін ДКЕ №1 із доповнення 10 до інструкції №114. */
    GOST28147_SBOX_ID_11 = 11, /**< Таблиця замін з ГОСТ 34.311-95. */
    GOST28147_SBOX_ID_12 = 12, /**< Таблиця замін CryptoPro-Test з RFC-4357. */
    GOST28147_SBOX_ID_13 = 13, /**< Таблиця замін CryptoPro-A з RFC-4357. */
    GOST28147_SBOX_ID_14 = 14, /**< Таблиця замін CryptoPro-B з RFC-4357. */
    GOST28147_SBOX_ID_15 = 15, /**< Таблиця замін CryptoPro-C з RFC-4357. */
    GOST28147_SBOX_ID_16 = 16, /**< Таблиця замін CryptoPro-D з RFC-4357. */
    GOST28147_SBOX_ID_17 = 17, /**< Таблиця замін id-GostR3411-94-CryptoProParamSet з RFC-4357. */
    GOST28147_SBOX_ID_18 = 18, /**< Таблиця замін з openssl */
} Gost28147SboxId;

/**
 * Створює контекст ГОСТ 28147 зі стандартною таблицею замін.
 *
 * @param sbox_id ідентифікатор стандартної таблиці замін
 * @return контекст ГОСТ 28147
 */
CRYPTONITE_EXPORT Gost28147Ctx *gost28147_alloc(Gost28147SboxId sbox_id);

/**
 * Створює контекст ГОСТ 28147 з користувацьким sbox.
 *
 * @param sbox користувацька таблиця замін разміром 128 байт
 * @return контекст ГОСТ 28147
 */
CRYPTONITE_EXPORT Gost28147Ctx *gost28147_alloc_user_sbox(const ByteArray *sbox);

CRYPTONITE_EXPORT Gost28147Ctx *gost28147_copy_with_alloc(const Gost28147Ctx *ctx);

/**
 * Повертає розгорнуту таблицю замін.
 *
 * @param ctx контекст ГОСТ 28147
 * @param sbox таблиця замін разміром 128 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_get_ext_sbox(const Gost28147Ctx *ctx, ByteArray **sbox);

/**
 * Повертає зжату таблицю замін.
 *
 * @param ctx контекст ГОСТ 28147
 * @param sbox таблиця замін разміром 128 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_get_compress_sbox(const Gost28147Ctx *ctx, ByteArray **sbox);

/**
 * Генерує секретний ключ відповідно до ГОСТ 28147-89.
 *
 * @param prng контекст ГПСЧ
 * @param key секретний ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_generate_key(PrngCtx *prng, ByteArray **key);

/**
 * Ініціалізує контекст для шифрування у режимі простої заміни.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_init_ecb(Gost28147Ctx *ctx, const ByteArray *key);

/**
 * Ініціалізує контекст для шифрування у режимі гамування.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_init_ctr(Gost28147Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі гамування зі зворотнім зв'язком.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @param iv синхропосилка
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_init_cfb(Gost28147Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для отримання імітовставки.
 *
 * @param ctx контекст ГОСТ 28147
 * @param key ключ шифрування
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_init_mac(Gost28147Ctx *ctx, const ByteArray *key);

/**
 * Шифрує блок даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param data дані для шифрування
 * @param encrypted_data зашифровані дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_encrypt(Gost28147Ctx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифровує блок даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_decrypt(Gost28147Ctx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Обновлюемо імітовектор блоком даних.
 *
 * @param ctx контекст ГОСТ 28147
 * @param data дані
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_update_mac(Gost28147Ctx *ctx, const ByteArray *data);

/**
 * Завершуе вироботку імітовектора і повертає його значення.
 *
 * @param ctx контекст ГОСТ 28147
 * @param mac імітовектор
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_final_mac(Gost28147Ctx *ctx, ByteArray **mac);

/**
 * Завершує вироботку імітовектора і повертає його розширене значення.
 *
 * @param ctx контекст ГОСТ 28147
 * @param mac розширений імітовектор
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int gost28147_final_mac8(Gost28147Ctx *ctx, ByteArray **mac);

/**
 * Звільняє контекст ГОСТ 28147.
 *
 * @param ctx контекст ГОСТ 28147
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT void gost28147_free(Gost28147Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
