/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __STORAGE_UTILS_PKCS12_H__
#define __STORAGE_UTILS_PKCS12_H__

#include "PFX.h"
#include "SafeContents.h"
#include "SafeBag.h"
#include "EncryptedPrivateKeyInfo.h"
#include "PrivateKeyInfo.h"
#include "byte_array.h"
#include "pkcs12.h"

typedef enum {
    FS_NOT_LOADED = 0,
    FS_ACTUAL_STATE = 1,
    FS_MODIFIED_STATE = 2
} FileStorageState;

typedef struct Pkcs5Params_st {
    ByteArray             *salt;
    unsigned long          iterations;
    AlgorithmIdentifier_t *encrypt_aid;
} Pkcs5Params;

typedef struct Pkcs12Contents_st {
    SafeContents_t *save_contents;
    Pkcs5Params  *params;
} Pkcs12Contents;

/** Структура ключевого хранилища. */
typedef struct Pkcs12IntStorage_st {
    FileStorageState state;             /** состояние хранилища */
    char            *name;              /** имя хранилища */
    Pkcs12Contents **contents;          /** контейнеры элементов хранилища */
    size_t           contents_len;      /** количество контейнеров */
    char            *password;          /** пароль хранилища */
    MacData_t       *mac_data;
} Pkcs12IntStorage;

typedef enum {KEY_BAG, PKCS8SHROUDEDKEY_BAG, CERT_BAG, CRL_BAG, SECRET_BAG, SAFECONTENTS_BAG} Pkcs12BagType_t;

/** Типы сертификатов хранилища. */
typedef enum {
    X509_CERT,
    SDSI_CERT,
    UNKNOWN_CERT
} CertType;

/** Структура сертификата хранилища. */
typedef struct Pkcs12Cert_st {
    ByteArray  *cert;       /**< сертификат */
    CertType type;       /**< тип сертификата */
} Pkcs12Cert;

/** Структура сертификатов хранилища. */
typedef struct Pcs12Certs_st {
    Pkcs12Cert **certs;       /**< сертификат */
    size_t          count;       /**< количество сертификатов */
} Pcs12Certs;

/**
 * Создает неинициализированный объект.
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
PFX_t *pfx_alloc(void);

/**
 * Освобождает память, занимаемую объектом.
 *
 * @param key удаляемый объект или NULL
 */
void pfx_free(PFX_t *container);

/**
 * Возвращает байтовое представление в DER-кодировании.
 * Выделяемая память требует освобождения.
 *
 * @param key контейнер закрытого ключа
 * @param out указатель на выделяемую память, содержащую DER-представление.
 * @param len актуальный размер данных
 *
 * @return код ошибки
 */
int pfx_encode(const PFX_t *container, ByteArray **encode);

/**
 * Инициализирует сертификат из DER-представления.
 *
 * @param key контейнер закрытого ключа
 * @param in буфер с байтами DER-кодирования
 * @param len размер данных
 *
 * @return код ошибки
 */
int pfx_decode(PFX_t *container, const ByteArray *encode);

/**
 * Створює порожню структуру MacData для заданого типу MAC.
 *
 * @param id       тип MAC (алгоритм гешування)
 * @param rounds   кількість ітерацій
 * @param mac_data створена структура MacData
 *
 * @return код помилки
 */
int pkcs12_create_empty_mac_data(Pkcs12MacType id, int rounds, MacData_t **mac_data);

/**
 * Переобчислює та оновлює MAC контейнера PFX.
 *
 * @param pfx  контейнер PFX
 * @param pass пароль сховища
 *
 * @return код помилки
 */
int pfx_update_mac_data(PFX_t *pfx, const char *pass);

/**
 * Розбирає вміст контейнера PFX у масив контейнерів сховища.
 *
 * @param container       контейнер PFX
 * @param password        пароль сховища
 * @param pkcs12_contents масив контейнерів вмісту
 * @param count           кількість контейнерів
 *
 * @return код помилки
 */
int pfx_get_contents(const PFX_t *container, const char *password, Pkcs12Contents ***pkcs12_contents, size_t *count);

/**
 * Создает неинициализированный объект.
 *
 * @return указатель на созданный объект или NULL в случае ошибки
 */
Pkcs12Contents **pkcs12_contents_alloc(size_t count);

/**
 * Освобождает память, занимаемую объектом.
 *
 * @param contents удаляемый объект или NULL
 */
void pkcs12_contents_arr_free(Pkcs12Contents **contents, size_t count);

/**
 * Визначає тип SafeBag за його OID.
 *
 * @param bag  SafeBag
 * @param type тип SafeBag
 *
 * @return код помилки
 */
int safebag_get_type(const SafeBag_t *bag, Pkcs12BagType_t *type);

/**
 * Повертає користувацьке ім'я (friendlyName) SafeBag або типове ім'я.
 *
 * @param bag   SafeBag
 * @param idx   індекс для формування типового імені
 * @param alias отримане ім'я
 *
 * @return код помилки
 */
int safebag_get_alias(const SafeBag_t *bag, int idx, char **alias);

/**
 * Формує контейнер вмісту із закритим ключем (за наявності пароля — зашифрованим).
 *
 * @param alias    користувацьке ім'я ключа або NULL
 * @param pass     пароль до ключа або NULL
 * @param key      закритий ключ
 * @param rounds   кількість ітерацій деривації
 * @param contents контейнер вмісту, що заповнюється
 *
 * @return код помилки
 */
int pkcs12_contents_set_key(const char *alias, const char *pass, const PrivateKeyInfo_t *key, int rounds,
        Pkcs12Contents *contents);

/**
 * Формує контейнер вмісту із сертифікатами.
 *
 * @param certs    список сертифікатів (null-terminated)
 * @param contents контейнер вмісту, що заповнюється
 *
 * @return код помилки
 */
int pkcs12_contents_set_certs(const ByteArray **certs, Pkcs12Contents *contents);

/**
 * Повертає сертифікати з контейнерів вмісту в байтовому представленні.
 *
 * @param contents     масив контейнерів вмісту
 * @param contents_len кількість контейнерів
 * @param certs        отриманий список сертифікатів (null-terminated)
 *
 * @return код помилки
 */
int pkcs12_contents_get_certificates(const Pkcs12Contents **contents, size_t contents_len, ByteArray ***certs);

/**
 * Обчислює MAC цілісності контейнера PFX.
 *
 * @param pfx  контейнер PFX
 * @param pass пароль сховища
 * @param mac  обчислений MAC
 *
 * @return код помилки
 */
int pfx_calc_mac(const PFX_t *pfx, const char *pass, ByteArray **mac);

/**
 * Перевіряє MAC цілісності контейнера PFX.
 *
 * @param pfx  контейнер PFX
 * @param pass пароль сховища
 *
 * @return код помилки
 */
int pfx_check_mac(const PFX_t *pfx, const char *pass);

#endif
