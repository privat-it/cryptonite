/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_DSTU7624_H
#define CRYPTONITE_DSTU7624_H

#include "byte_array.h"
#include "prng.h"

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * Контекст для dstu7624.
 */
typedef struct Dstu7624Ctx_st Dstu7624Ctx;

typedef enum {
    DSTU7624_SBOX_1 = 0 /*Стандартний sbox ДСТУ7624 */
} Dstu7624SboxId;

/**
 * Створює контекст ДСТУ 7624 зі стандартним sbox.
 *
 * @param sbox_id ідентифікатор стандартної таблиці замін
 * @return контекст ДСТУ 7624
 */
CRYPTONITE_EXPORT Dstu7624Ctx *dstu7624_alloc(Dstu7624SboxId sbox_id);

/**
 * Створює контекст ДСТУ 7624 з користувацьким sbox.
 *
 * @param sbox користувацький sbox
 * @return контекст ДСТУ 7624
 */
CRYPTONITE_EXPORT Dstu7624Ctx *dstu7624_alloc_user_sbox(ByteArray *sbox);

/**
 * Генерує секретний ключ.
 *
 * @param prng контекст ГПСЧ
 * @param key_len розмір ключа 16, 32 или 64
 * @param key секретний ключ
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_generate_key(PrngCtx *prng, size_t key_len, ByteArray **key);

/**
 * Ініціалізує контекст для шифрування у режимі простої заміни.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param block_size розмір блока, 16, 32, 64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_ecb(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size);

/**
 * Ініціалізує контекст для шифрування у режимі гамування.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка, розміром блоку
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_ctr(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі гамування з обратним зв'язком.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @param q кількість байт, які будуть шифруватися за один цикл, 1 <= q <= block_size
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_cfb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q);

/**
 * Ініціалізує контекст для шифрування у режимі зчеплення шифроблоків.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_cbc(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі гамування зі зворотним зв'язком по шифрограммі.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_ofb(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі вибіркового гамування з прискореною виробкою імітовставки.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @param q розмір імітовставки, 1 <= q <= block_size
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_gcm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q);

/**
 * Ініціалізує контекст для обчислення імітовставки.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param block_size розмір блока, 16, 32, 64 байт
 * @param q довжина імітовставки.
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_cmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size,
        const size_t q);

/**
 * Ініціалізує контекст для шифрування у режимі вибіркового гамування з прискореною виробкою імітовставки.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param block_size розмір блока, 16, 32, 64 байт
 * @param q розмір імітовставки, 1 <= q <= block_size
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_gmac(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size,
        const size_t q);

/**
 * Ініціалізує контекст для шифрування у режимі виробки імітовставки і гамування.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @param q розмір імітовставки, 1 <= q <= block_size
 * @param n_max найбільша можлива довжина відкритої або конфіденційної частини повідомлення (в бітах)
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_ccm(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv, const size_t q,
        uint64_t n_max);

/**
 * Ініціалізує контекст для шифрування у режимі індексованої заміни.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param iv синхропосилка розміром блоку, 16, 32, 64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_xts(Dstu7624Ctx *ctx, const ByteArray *key, const ByteArray *iv);

/**
 * Ініціалізує контекст для шифрування у режимі захисту ключових даних.
 *
 * @param ctx контекст ДСТУ 7624
 * @param key ключ шифрування
 * @param block_size розмір блока, 16, 32, 64 байт
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_init_kw(Dstu7624Ctx *ctx, const ByteArray *key, const size_t block_size);

/**
 * Шифрування та вироблення імітовставки.
 *
 * @param ctx контекст ДСТУ 7624
 * @param auth_data відкритий текст повідомлення
 * @param data дані для шифрування
 * @param mac імітовставка
 * @param encrypted_data зашифроване повідомлення
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_encrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data, const ByteArray *data,
        ByteArray **mac, ByteArray **encrypted_data);

/**
 * Розшифрування та забезпечення цілосності.
 *
 * @param ctx контекст ДСТУ 7624
 * @param auth_data відкритий текст повідомлення
 * @param encrypted_data дані для розшифрування
 * @param mac імітовставка
 * @param data розшифроване повідомлення
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_decrypt_mac(Dstu7624Ctx *ctx, const ByteArray *auth_data,
        const ByteArray *encrypted_data, ByteArray *mac, ByteArray **data);

/**
 * Шифрування даних.
 *
 * @param ctx контекст ДСТУ 7624
 * @param data дані для шифрування
 * @param encrypted_data зашифровані дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_encrypt(Dstu7624Ctx *ctx, const ByteArray *data, ByteArray **encrypted_data);

/**
 * Розшифрування даних.
 *
 * @param ctx контекст ДСТУ 7624
 * @param encrypted_data зашифровані дані
 * @param data розшифровані дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_decrypt(Dstu7624Ctx *ctx, const ByteArray *encrypted_data, ByteArray **data);

/**
 * Доповнює імітовставку блоком даних.
 *
 * @param ctx контекст ДСТУ 7624
 * @param data дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_update_mac(Dstu7624Ctx *ctx, const ByteArray *data);

/**
 * Завершує виробку імітовставки і повертає її значення.
 *
 * @param ctx контекст ДСТУ 7624
 * @param mac імітовставка
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dstu7624_final_mac(Dstu7624Ctx *ctx, ByteArray **mac);

/**
 * Звільняє контекст ДСТУ 7624.
 *
 * @param ctx контекст ДСТУ 7624
 */
CRYPTONITE_EXPORT void dstu7624_free(Dstu7624Ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif
