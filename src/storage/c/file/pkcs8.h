/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __STORAGE_PKCS8_H__
#define __STORAGE_PKCS8_H__

#include "PrivateKeyInfo.h"
#include "byte_array.h"
#include "sign_adapter.h"
#include "verify_adapter.h"
#include "dh_adapter.h"

/** Типи ключів контейнера. */
typedef enum {
    PRIVATEKEY_DSTU = 0,
    PRIVATEKEY_RSA = 1,
    PRIVATEKEY_DSA = 2,
    PRIVATEKEY_ECDSA = 3,
    PRIVATEKEY_GOST3410 = 4,
    PRIVATEKEY_UNKNOWN = 5
} Pkcs8PrivatekeyType;

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT PrivateKeyInfo_t *pkcs8_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param key об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void pkcs8_free(PrivateKeyInfo_t *key);

/**
 * Генерує контейнер з закритим ключем.
 *
 * @param aid алгоритм закритого ключа
 * @param key контейнер закритого ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_generate(const AlgorithmIdentifier_t *aid, PrivateKeyInfo_t **key);

/**
 * Ініціалізує контейнер.
 *
 * @param key     контейнер закритого ключа
 * @param privkey закритий ключ
 * @param aid     алгоритм закритого ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_init(PrivateKeyInfo_t *key, const ByteArray *privkey, const AlgorithmIdentifier_t *aid);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param key    контейнер закритого ключа
 * @param encode вказівник на пам'ять, що виділяється, яка містить DER-представлення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_encode(const PrivateKeyInfo_t *key, ByteArray **encode);

/**
 * Ініціалізує сертифікат з DER-представлення.
 *
 * @param key    контейнер закритого ключа
 * @param encode буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_decode(PrivateKeyInfo_t *key, const ByteArray *encode);

/**
 * Повертає тип сховища.
 *
 * @param key  контейнер закритого ключа
 * @param type тип ключа контейнера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_type(const PrivateKeyInfo_t *key, Pkcs8PrivatekeyType *type);

/**
 * Повертає закритий ключ.
 *
 * @param key     контейнер з закритим ключем
 * @param privkey закритий ключ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_privatekey(const PrivateKeyInfo_t *key, ByteArray **privkey);

/**
 * Повертає закритий ключ  ДСТУ 4145 для виробки спільного секрету у форматі Big-Endian.
 *
 * @param private_key контейнер з закритим ключем
 * @param d           закритий ключ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_kep_privatekey(const PrivateKeyInfo_t *private_key, ByteArray **d);

/**
 * Формує структуру SubjectPublicKeyInfo для відкритого ключа.
 *
 * @param key  контейнер з закритим ключем
 * @param spki SubjectPublicKeyInfo
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_spki(const PrivateKeyInfo_t *key, SubjectPublicKeyInfo_t **spki);

/**
 * Повертає контекст виробки підпису.
 *
 * @param key  контейнер з закритим ключем
 * @param cert буфер з сертифікатом
 * @param sa   контекст виробки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_sign_adapter(const PrivateKeyInfo_t *key, const ByteArray *cert,
        SignAdapter **sa);

/**
 * Повертає контекст перевірки підпису.
 *
 * @param key контейнер з закритим ключем
 * @param va  контекст перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_verify_adapter(const PrivateKeyInfo_t *key, VerifyAdapter **va);

/**
 * Повертає контекст wrap adapter.
 *
 * @param key контейнер з закритим ключем
 * @param ctx контекст wrap адаптера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkcs8_get_dh_adapter(const PrivateKeyInfo_t *key, DhAdapter **ctx);

#endif
