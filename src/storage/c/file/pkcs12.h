/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __STORAGE_PKCS12_H__
#define __STORAGE_PKCS12_H__

#include "sign_adapter.h"
#include "verify_adapter.h"
#include "dh_adapter.h"

#define FILE_STORAGE_PKCS12  "PKCS12"

#define KEY_TYPE_UNKNOWN     "UNKNOWN"
#define KEY_TYPE_DSTU        "DSTU4145"
#define KEY_TYPE_ECDSA       "ECDSA"

#define PKCS8_CERT_PREF      "PKCS12-"

#ifdef  __cplusplus
extern "C" {
#endif

/** Типи ключового сховища. */
typedef enum {
    KS_FILE_PKCS12_UNKNOWN = 0,
    KS_FILE_PKCS12_WITH_GOST34311 = 1,
    KS_FILE_PKCS12_WITH_SHA1 = 2,
    KS_FILE_PKCS12_WITH_SHA224 = 3,
    KS_FILE_PKCS12_WITH_SHA256 = 4,
    KS_FILE_PKCS12_WITH_SHA384 = 5,
    KS_FILE_PKCS12_WITH_SHA512 = 6,
} Pkcs12MacType;

/** Типи аутентифікації для роботи з ключем. */
typedef enum AuthType_st {
    AUTH_KEY_PASS = 0,
    AUTH_NO_PASS = 1,
    AUTH_STORAGE_PASS = 2
} Pkcs12AuthType;

/** Ключова пара. */
typedef struct Pkcs12Keypair_st {
    /** ім'я ключової пари */
    const char *const alias;
    /** тип аутенифікації для роботи з ключовою парою */
    const Pkcs12AuthType auth;
    /** внутрішній ідентифікатор */
    const int int_id;
} Pkcs12Keypair;

typedef struct Pkcs12StorageCtx_st Pkcs12Ctx;

/**
 * Повертає користувацьке ім'я сховища.
 *
 * @param ctx сховище
 * @param name рядок з назвою вбудовування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_storage_name(const Pkcs12Ctx *ctx, const char *const *name);

/**
 * Змінює пароль до сховища.
 *
 * @param ctx сховище
 * @param cur_pwd поточний пароль до сховища або NULL
 * @param new_pwd новий пароль до сховища або NULL
 * @param remained_attempts кількість спроб, які залишилися для введення паролю, -1 значить нескінченно
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_change_password(Pkcs12Ctx *ctx, const char *cur_pwd, const char *new_pwd);

/**
 * Отримання списку ключів.
 *
 * @param ctx сховище
 * @param keys список ключів зі сховища
 * @param cnt кількість ключів у списку
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_enum_keys(Pkcs12Ctx *ctx, const Pkcs12Keypair *const *keys, const size_t *cnt);

/**
 * Вибір ключа.
 *
 * @param ctx сховище
 * @param alias ключ
 * @param pwd користувацький пароль до ключа або NULL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_select_key(Pkcs12Ctx *ctx, const char *alias, const char *pwd);

/**
 * Генерує нову пару асиметричних ключів з певними параметрами.
 *
 * @param ctx сховище
 * @param aid AlgorithmIdentifier в байтовому представленні
 * @param key згенерований ключ (не входить в список основних ключів сховища)
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_generate_key(Pkcs12Ctx *ctx, const ByteArray *aid);

/**
 * Чи згенерований новий ключ?
 *
 * @param ctx сховище
 * @param is_generated true - згенерований, false - ще ні
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_is_key_generated(const Pkcs12Ctx *ctx, bool *is_generated);

/**
 * Зберігає згенерований ключ.
 *
 * @param ctx    сховище
 * @param alias  користувацьке ім'я ключа
 * @param pwd    користувацький пароль до ключа або NULL
 * @param rounds кількість раундів хешування паролю
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_store_key(Pkcs12Ctx *ctx, const char *alias, const char *pwd, int rounds);

/**
 * Зберігає сертифікати.
 *
 * @param ctx   сховище
 * @param certs список з вказівників на байтові представлення сертифікатів (null-terminated)
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_set_certificates(Pkcs12Ctx *ctx, const ByteArray **certs);

/**
 * Повертає байтове представлення сертифікату ключа.
 *
 * @param ctx       сховище
 * @param key_usage бітова маска областей застосування сертифікату, які перевіряються
 * @param cert      байтове представлення сертифікату ключа або NULL у випадку відсутності
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_certificate(const Pkcs12Ctx *ctx, int key_usage, ByteArray **cert);

/**
 * Повертає список сертифікатів ключа в байтовому представленні.
 *
 * @param ctx   сховище
 * @param certs байтове представлення списку сертифікатів або NULL у випадку відсутності (null-terminated)
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_certificates(const Pkcs12Ctx *ctx, ByteArray ***certs);

/**
 * Створює движок підпису.
 *
 * @param ctx сховище
 * @param sa  ініціалізований контекст движка підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_sign_adapter(const Pkcs12Ctx *ctx, SignAdapter **sa);

/**
 * Ініціалізує dh adapter.
 *
 * @param ctx сховище
 * @param dha dh adapter
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_dh_adapter(const Pkcs12Ctx *ctx, DhAdapter **dha);

/**
 * Створює движок перевірки підпису.
 *
 * @param storage сховище
 * @param va ініціалізований контекст движка перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_get_verify_adapter(const Pkcs12Ctx *ctx, VerifyAdapter **va);

/**
 * Зберігає файлове сховище в байтовому представленні.
 *
 * @param ctx     контекст сховища
 * @param storage_body байтове представлення сховища
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_encode(const Pkcs12Ctx *ctx, ByteArray **storage_body);

/**
 * Очищує всі контексти роботи зі сховищем.
 *
 * @param storage сховище
 */
CRYPTONITE_EXPORT void pkcs12_free(Pkcs12Ctx *ctx);

/**
 * Отримує сховище невідомого типу з його байтового представлення.
 * Використовується послідовний перебір типів вбудовування.
 *
 * @param storage_name ім'я сховища
 * @param storage_body байтове представлення сховища
 * @param password пароль до сховища
 * @param storage контекст сховища
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_decode(const char *storage_name, const ByteArray *storage_body, const char *password,
        Pkcs12Ctx **storage);

/**
 * Створює файлове сховище заданого типу.
 *
 * @param type тип сховища
 * @param password пароль до сховища
 * @param rounds кількість раундів хешування паролю
 * @param storage контекст сховища
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs12_create(Pkcs12MacType type, const char *password, int rounds, Pkcs12Ctx **storage);

#ifdef __cplusplus
}
#endif

#endif
