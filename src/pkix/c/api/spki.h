/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SRC_PKIX_C_API_SPKI_H_
#define SRC_PKIX_C_API_SPKI_H_

#include "pkix_structs.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT SubjectPublicKeyInfo_t *spki_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param spki об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void spki_free(SubjectPublicKeyInfo_t *spki);

/**
 * Повертає байтове представлення об'єкта в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param spki ідентифікатор параметрів алгоритму
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int spki_encode(const SubjectPublicKeyInfo_t *spki, ByteArray **out);

/**
 * Ініціалізує aid из DER-представлення.
 *
 * @param spki ідентифікатор параметрів алгоритму
 * @param in  буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int spki_decode(SubjectPublicKeyInfo_t *spki, const ByteArray *in);

/**
 * Повертає відкритий ключ в байтовому little-endian представленні.
 * Підтримується ДСТУ 4145.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param spki        сертифікат
 * @param pub_key     буфер для зберігання байтового представлення відкритого ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int spki_get_pub_key(const SubjectPublicKeyInfo_t *spki, ByteArray **pub_key);

#ifdef __cplusplus
}
#endif

#endif
