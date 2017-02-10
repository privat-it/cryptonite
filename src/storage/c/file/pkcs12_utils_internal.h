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
 * �?нициализирует сертификат из DER-представления.
 *
 * @param key контейнер закрытого ключа
 * @param in буфер с байтами DER-кодирования
 * @param len размер данных
 *
 * @return код ошибки
 */
int pfx_decode(PFX_t *container, const ByteArray *encode);

int pkcs12_create_empty_mac_data(Pkcs12MacType id, int rounds, MacData_t **mac_data);

int pfx_update_mac_data(PFX_t *pfx, const char *pass);

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

int safebag_get_type(const SafeBag_t *bag, Pkcs12BagType_t *type);

int safebag_get_alias(const SafeBag_t *bag, int idx, char **alias);

int pkcs12_contents_set_key(const char *alias, const char *pass, const PrivateKeyInfo_t *key, int rounds,
        Pkcs12Contents *contents);

int pkcs12_contents_set_certs(const ByteArray **certs, Pkcs12Contents *contents);

int pkcs12_contents_get_certificates(const Pkcs12Contents **contents, size_t contents_len, ByteArray ***certs);

int pfx_calc_mac(const PFX_t *pfx, const char *pass, ByteArray **mac);

int pfx_check_mac(const PFX_t *pfx, const char *pass);

#endif
