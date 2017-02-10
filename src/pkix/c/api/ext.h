/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __EXT_H__
#define __EXT_H__

#include <stdbool.h>
#include <time.h>

#include "pkix_structs.h"
#include "oids.h"
#include "digest_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює розширення по безпосередньому значенню.
 *
 * @param critical прапорець критичності розширення
 * @param oid OID розширення
 * @param value значення розширення
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_any(bool critical, OidNumbers *oid, const ByteArray *value, Extension_t **ext);

/**
 * Створює розширення ідентифікатора ключа підписчика.
 *
 * @param critical прапорець критичності розширення
 * @param issuer_cert сертифікат підписчика
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_auth_key_id_from_cert(bool critical, const Certificate_t *issuer_cert,
        Extension_t **ext);

/**
 * Створює розширення ідентифікатора ключа підписчика.
 * Використовується для самопідписуємого сертифікату.
 *
 * @param critical прапорець критичності розширення
 * @param spki публічний ключ суб'єкта
 * @param da адаптер для обчислення ідентифікатору
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_auth_key_id_from_spki(bool critical, const SubjectPublicKeyInfo_t *spki,
        Extension_t **ext);

/**
 * Створює розширення про доступ до інформації про центри сертифікації.
 *
 * @param critical прапорець критичності розширення
 * @param oids масив OID'ов опису доступу
 * @param name_uris масив uri, які містять відомості про центри сертифікації
 * @param cnt кількість елементів в масивах oids, name_uris
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_auth_info_access(bool critical, OidNumbers **oids, const char **name_uris, int cnt,
        Extension_t **ext);

/**
 * Створює розширення основних обмежень.
 *
 * @param critical прапорець критичності розширення
 * @param issuer об'єкт розширення, який належить стороні, яка підписує, або NULL
 * @param ca прапорець УЦ, якщо true - публічний ключ сертифікату належить УЦ
 * @param path_len_constraint максимальна кількість проміжних сертифікатів
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_basic_constraints(bool critical, const BasicConstraints_t *issuer, bool ca,
        int path_len_constraint, Extension_t **ext);

/**
 * Створює розширення політики сертифікатів.
 *
 * @param critical прапорець критичності розширення
 * @param oids масив OID'ів, які визначають політики сертифікату
 * @param cnt кількість елементів в масиві oids
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_cert_policies(bool critical, OidNumbers **oids, int cnt, Extension_t **ext);

/**
 * Створює розширення точок розповсюдження CRL.
 *
 * @param critical прапорець критичності розширення
 * @param point_uris масив uri для точок розповсюдження
 * @param cnt кількість елементів в масиві point_uris
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_crl_distr_points(bool critical, const char **point_uris, int cnt, Extension_t **ext);

/**
 * Створює розширення ідентифікатору CRL(CrlID).
 *
 * @param critical прапорець критичності розширення
 * @param distr_url якщо != NULL, розміщує відповідний елемент в розширенні
 * @param crl_number якщо != NULL, розміщує відповідний елемент в розширенні
 * @param crl_time якщо != NULL, розміщує відповідний елемент в розширенні
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_crl_id(bool critical, char *distr_url, ByteArray *crl_number, time_t *crl_time,
        Extension_t **ext);

/**
 * Створює розширення серійного номеру.
 *
 * @param critical прапорець критичності розширення
 * @param crl_sn серійний номер
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_crl_number(bool critical, const ByteArray *crl_sn, Extension_t **ext);

/**
 * Створює розширення причини відклику сертифікату.
 *
 * @param critical прапорець критичності розширення
 * @param reason причина відклику, перерахування типу e_CRLReason
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_crl_reason(bool critical, const CRLReason_t *reason, Extension_t **ext);

/**
 * Створює розширення серійного номеру повного CRL.
 *
 * @param critical прапорець критичності розширення
 * @param crl серійний номер батьківського CRL
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_delta_crl_indicator(bool critical, const ByteArray *crl_number, Extension_t **ext);

/**
 * Створює розширення поліпшеного ключа.
 *
 * @param critical прапорець критичності розширення
 * @param oids масив OID'ів призначення ключа
 * @param cnt кількість елементів в масиві oids
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_ext_key_usage(bool critical, OBJECT_IDENTIFIER_t **oids, int cnt, Extension_t **ext);

/**
 * Створює розширення новітнього CRL.
 *
 * @param critical прапорець критичності розширення
 * @param point_uris масив uri для точок розповсюдження
 * @param cnt кількість елеметів в масиві point_uris
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_freshest_crl(bool critical, const char **point_uris, int cnt, Extension_t **ext);

/**
 * Створює розширення часу компрометації ключа.
 *
 * @param critical прапорець критичності розширення
 * @param date час компрометації ключа
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_invalidity_date(bool critical, const time_t *date, Extension_t **ext);

/** Призначення ключів. */
typedef enum {
    KEY_USAGE_DIGITAL_SIGNATURE = (int)0x00000001,
    KEY_USAGE_NON_REPUDIATION = (int)0x00000002,
    KEY_USAGE_KEY_ENCIPHERMENT = (int)0x00000004,
    KEY_USAGE_DATA_ENCIPHERMENT = (int)0x00000008,
    KEY_USAGE_KEY_AGREEMENT = (int)0x00000010,
    KEY_USAGE_KEY_CERTSIGN = (int)0x00000020,
    KEY_USAGE_CRL_SIGN = (int)0x00000040,
    KEY_USAGE_ENCIPHER_ONLY = (int)0x00000080,
    KEY_USAGE_DECIPHER_ONLY = (int)0x00000100
} KeyUsageBits;

/**
 * Створює розширення використання ключа.
 *
 * @param critical прапорець критичності розширення
 * @param usage_bits параметри використання ключа (бітова маска з перерахування типу key_usage_t)
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_key_usage(bool critical, KeyUsageBits usage_bits, Extension_t **ext);

/**
 * Створює розширення періоду використання ключа.
 * Якщо вказаний термін дії сертифікату, то він має пріоритет над
 * часом початку та закінчення дії ключа.
 *
 * @param critical прапорець критичності розширення
 * @param validity термін дії сертифікату або NULL
 * @param not_before термін початку використання ключа або NULL
 * @param not_after термін закінчення використання ключа або NULL
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_private_key_usage(bool critical, const Validity_t *validity, const time_t *not_before,
        const time_t *not_after, Extension_t **ext);

CRYPTONITE_EXPORT int ext_create_qc_statement_compliance(QCStatement_t **qc_statement);

CRYPTONITE_EXPORT int ext_create_qc_statement_limit_value(const char *currency_code, long amount, long exponent,
        QCStatement_t **out);

/**
 * Створює розширення декларації перевірених сертифікатів.
 *
 * @param critical прапорець критичності розширення
 * @param qc_statements масив опціональних додаткових параметрів
 * @param cnt кількість елементів в масивах qc_statements та params
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_qc_statements(bool critical, QCStatement_t **qc_statements, size_t qc_statements_len,
        Extension_t **ext);

/**
 * Створює розширення альтернативного імені суб'єкта по безпосереднім значенням.
 *
 * @param critical прапорець критичності розширення
 * @param types типи імен
 * @param names масив рядків (імена)
 * @param cnt кількість елементів в масивах types та names
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_subj_alt_name_directly(bool critical, enum GeneralName_PR *types, const char **names,
        int cnt, Extension_t **ext);

/**
 * Створює розширення атрибутів.
 *
 * @param critical прапорець критичності розширення
 * @param subject_attr розширення
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_subj_dir_attr_directly(bool critical, const char *subject_attr, Extension_t **ext);

/**
 * Створює розширення "Отримувач сертифікату доступу до інформації".
 *
 * @param critical прапорець критичності розширення
 * @param oids масив OID'ів опису доступу
 * @param name_uris масив uri, які містять відомості про розташування доступу
 * @param cnt кількість елементів в масивах oids, name_uris
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_subj_info_access(bool critical, OidNumbers **oids, const char **name_uris, int cnt,
        Extension_t **ext);

/**
 * Створює розширення ідентифікатору ключа суб'єкта.
 *
 * @param critical прапорець критичності розширення
 * @param spki публічний ключ суб'єкта
 * @param da адаптер для обчислення ідентифікатору
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_subj_key_id(bool critical, const SubjectPublicKeyInfo_t *spki, Extension_t **ext);

/**
 * Створює розширення Nonce.
 *
 * @param critical прапорець критичності розширення
 * @param rnd_bts випадкові байти
 * @param ext вказівник на створюване розширення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ext_create_nonce(bool critical, const ByteArray *rnd_bts, Extension_t **ext);

CRYPTONITE_EXPORT int ext_get_value(const Extension_t *ext, ByteArray **value);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param ext об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void ext_free(Extension_t *ext);

#ifdef __cplusplus
}
#endif

#endif
