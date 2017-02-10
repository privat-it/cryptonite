/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_API_CONTENT_INFO_H
#define CRYPTONITE_PKI_API_CONTENT_INFO_H

#include "pkix_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONTENT_DATA = 0,
    CONTENT_SIGNED = 1,
    CONTENT_DIGESTED = 2,
    CONTENT_ENCRYPTED = 3,
    CONTENT_ENVELOPED = 4,
    CONTENT_UNKNOWN = 5
} CinfoType;

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT ContentInfo_t *cinfo_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param cinfo об'єкт, який видаляється або NULL
 */
CRYPTONITE_EXPORT void cinfo_free(ContentInfo_t *cinfo);

/**
 * Ініціалізує контейнер контейнером підписаних даних.
 *
 * @param cinfo контейнер даних
 * @param sdata контейнер підписаних даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_signed_data(ContentInfo_t *cinfo, const SignedData_t *sdata);

/**
 * Ініціалізує контейнер контейнером гешованих даних.
 *
 * @param cinfo контейнер даних
 * @param ddata контейнер гешованих даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_digest_data(ContentInfo_t *cinfo, const DigestedData_t *ddata);

/**
 * Ініціалізує контейнер контейнером шифрованих даних.
 *
 * @param cinfo контейнер даних
 * @param encr_data контейнер шифрованих даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_encrypted_data(ContentInfo_t *cinfo, const EncryptedData_t *encr_data);

/**
 * Ініціалізує контейнер даних.
 *
 * @param cinfo контейнер даних
 * @param data дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_data(ContentInfo_t *cinfo, const ByteArray *data);

/**
 * Ініціалізує контейнер контейнером захищених даних.
 *
 * @param cinfo контейнер даних
 * @param env_data контейнер захищених даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_enveloped_data(ContentInfo_t *cinfo, const EnvelopedData_t *env_data);

/**
 * Ініціалізує контейнер з заданням типу контейнера.
 *
 * @param cinfo контейнер даних
 * @param ctype тип контейнера
 * @param content дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_init_by_any_content(ContentInfo_t *cinfo, const ContentType_t *ctype, const ANY_t *content);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param out вказівник на пам'ять, яка виділяється, яка містить DER-представлення.
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_encode(const ContentInfo_t *cinfo, ByteArray **out);

/**
 * Ініціалізує  ContentInfo з DER-представлення.
 *
 * @param cinfo контейнер даних
 * @param in буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_decode(ContentInfo_t *cinfo, const ByteArray *in);

/**
 * Перевіряє, чи наявні дані.
 *
 * @param cinfo контейнер даних
 * @param flag прапорець наявності даних в контейнері
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_has_content(const ContentInfo_t *cinfo, bool *flag);

/**
 * Повертає контейнер даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param data створюваний об'єкт контейнера даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_data(const ContentInfo_t *cinfo, ByteArray **data);

/**
 * Повертає контейнер підписаних даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param sdata створюваний об'єкт контейнера підписаних даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_signed_data(const ContentInfo_t *cinfo, SignedData_t **sdata);

/**
 * Повертає контейнер гешованих даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param ddata створюваний об'єкт контейнера гешованих даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_digested_data(const ContentInfo_t *cinfo, DigestedData_t **ddata);

/**
 * Повертає контейнер шифрованих даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param encr_data створюваний об'єкт контейнера шифрованих даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_encrypted_data(const ContentInfo_t *cinfo, EncryptedData_t **encr_data);

/**
 * Повертає контейнер захищених даних.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param env_data створюваний об'єкт контейнера захищених даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_enveloped_data(const ContentInfo_t *cinfo, EnvelopedData_t **env_data);

/**
 * Повертає контейнер даних та його тип.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param cinfo контейнер даних
 * @param ctype створюваний об'єкт типу контейнера
 * @param content створюваний об'єкт контейнера даних
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_any_content(const ContentInfo_t *cinfo, ContentType_t **ctype, ANY_t **content);

/**
 * Повертає тип контейнера.
 *
 * @param cinfo контейнер даних
 * @param type тип контейнера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cinfo_get_type(const ContentInfo_t *cinfo, CinfoType *type);

#ifdef __cplusplus
}
#endif

#endif
