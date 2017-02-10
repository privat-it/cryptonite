/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKIX_UTILS_H
#define CRYPTONITE_PKIX_UTILS_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "oids.h"
#include "byte_array.h"

#ifdef __cplusplus
extern "C" {
#endif

CRYPTONITE_EXPORT void certs_free(ByteArray **certs);

CRYPTONITE_EXPORT int get_cert_set_from_cert_array(const ByteArray **certs, CertificateSet_t **certs_set);

CRYPTONITE_EXPORT int get_cert_by_sid_and_usage(const SignerIdentifier_t *sid, int key_usage,
        const CertificateSet_t *certs, Certificate_t **cert);

CRYPTONITE_EXPORT int get_cert_by_usage(int key_usage, const ByteArray **certs, ByteArray **cert);

CRYPTONITE_EXPORT ByteArray *get_encoded_tbs_from_tbs(TBSCertificate_t *tbs);

/**
 * Обгортує підпис в BIT_STRING у форматі, який відповідає заданому алгоритму.
 *
 * @param sign значення підпису, отримане з адаптера
 * @param aid алгоритм підпису
 * @param sign_bitstring BIT_STRING підпису, який ініціалізується
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_ba_to_bs(const ByteArray *sign, const AlgorithmIdentifier_t *aid,
        BIT_STRING_t *sign_bitstring);

/**
 * Обгортує підпис в OCTET_STRING у форматі, який відповідає заданому алгоритму.
 *
 * @param sign       значення підпису, отримане з адаптера
 * @param aid        алгоритм підпису
 * @param sign_octet OCTET_STRING підпису, який ініціалізується
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_ba_to_os(const ByteArray *sign, const AlgorithmIdentifier_t *aid,
        OCTET_STRING_t **sign_octet);

/**
 * Розгортує підпис з BIT_STRING в байтовий масив.
 *
 * @param sign_bitstring BIT_STRING підпису
 * @param aid алгоритм підпису
 * @param sign значення підпису в байтовому представленні
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_bs_to_ba(const BIT_STRING_t *sign_bitstring, const AlgorithmIdentifier_t *aid,
        ByteArray **sign);

/**
 * Розгортує підпис з OCTET_STRING в байтовий масив.
 *
 * @param sign_os  OCTET_STRING підпису
 * @param aid      алгоритм підпису
 * @param sign     значення підпису в байтовому представленні
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_os_to_ba(const OCTET_STRING_t *sign_os, const AlgorithmIdentifier_t *aid, ByteArray **sign);

/**
 * Конвертує відкритий ключ з ASN1Bitstring в байтове little-endian представлення.
 * Підтримується ДСТУ 4145.
 *
 * @param signature_oid алгоритм підпису
 * @param pub_key_asn відкритий ключ у форматі BIT STRING з сертифіката
 * @param pub_key_ba буфер для зберігання байтового представлення відкритого ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int convert_pub_key_bs_to_ba(const OBJECT_IDENTIFIER_t *signature_oid,
        const BIT_STRING_t *pub_key_asn, ByteArray **pub_key_ba);

/**
 * Конвертує відкритий ключ з байтового little-endian представлення в ASN1Bitstring.
 *
 * (*out_pub_key_bs == NULL) - пам'ять під відповідь виділяється та потребує подальшого вивільнення.
 * (*out_pub_key_bs != NULL) - якщо пам'ять під повертаємий об'єкт вже виділена.
 *
 * @param signature_oid  алгоритм підпису
 * @param pub_key        байтове значення відкритого ключа в little-endian представленні
 * @param out_pub_key_bs представлення відкритого ключа
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int convert_pubkey_bytes_to_bitstring(const OBJECT_IDENTIFIER_t *signature_oid,
        const ByteArray *pub_key, BIT_STRING_t **out_pub_key_bs);

/**
 * Парсить строку вигляду "{key1=value1}{key2=value2}..{keyN=valueN}"
 * та повертає масиви строк зі значеннями ключів та значень.
 *
 * @param str строка
 * @param keys вказівник для ключів
 * @param values вказівник для значень
 * @param count кількість пар ключ-значення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int parse_key_value(const char *str, char ***keys, char ***values, size_t *count);

/**
 * Створює об'єкт Attribute по заданим значенням.
 *
 * @param attr об'єкт атрибута
 * @param oid об'єктний ідентифікатор
 * @param descriptor дескриптор типу даних
 * @param value дані
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int init_attr(Attribute_t **attr, const OidNumbers *oid, asn_TYPE_descriptor_t *descriptor,
        void *value);

/**
 * Знаходить атрибут по OIDу.
 *
 * @param attrs набір атрибутів
 * @param oid ідентифікатор шуканого атрибута
 * @param attr буфер для знайденого атрибута
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int get_attr_by_oid(const Attributes_t *attrs, const OBJECT_IDENTIFIER_t *oid, Attribute_t **attr);

/**
 * Перевіряє представлення параметрів ДСТУ 4145.
 *
 * @param oid           перевіряємий OID
 * @return true  - little-endian
 *         false - інше
 */
CRYPTONITE_EXPORT bool is_dstu_le_params(const OBJECT_IDENTIFIER_t *oid);

/**
 * Перевіряє представлення параметрів ДСТУ 4145.
 *
 * @param oid           перевіряємий OID
 * @return true  - big-endian
 *         false - інше
 */
CRYPTONITE_EXPORT bool is_dstu_be_params(const OBJECT_IDENTIFIER_t *oid);

CRYPTONITE_EXPORT int get_cert_set_by_sid(const CertificateSet_t *cert_set_in, const SignerIdentifier_t *sid,
        CertificateSet_t **cert_set_out);

CRYPTONITE_EXPORT int utf16be_to_utf8(const unsigned char *in, size_t in_len, char **out);
CRYPTONITE_EXPORT int utf8_to_utf16be(const char *in, unsigned char **out, size_t *out_len);

CRYPTONITE_EXPORT char *dupstr(const char *str);

/**
 * Перевіряє входження заданого OID`а в інший (батьківський) OID.
 *
 * @param oid        перевіряємий OID
 * @param parent_oid int-представлення батьківського OID`а
 *
 * @return true  - OID входить в батьківський
 *         false - OID не входить в батьківський
 */
CRYPTONITE_EXPORT bool pkix_check_oid_parent(const OBJECT_IDENTIFIER_t *oid, const OidNumbers *parent_oid);

CRYPTONITE_EXPORT int pkix_create_oid(const OidNumbers *oid, OBJECT_IDENTIFIER_t **dst);

/**
 * Порівнює два OID.
 *
 * @param oid         OID
 * @param oid_arr вказівник на буфер для int`ов
 *
 * @return чи рівні вони
 */
CRYPTONITE_EXPORT bool pkix_check_oid_equal(const OBJECT_IDENTIFIER_t *oid, const OidNumbers *oid_arr);

/**
 * Встановлює OID по int`му представленню.
 *
 * @param oid  вказівник на буфер для int`ов
 * @param dst  OID
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int pkix_set_oid(const OidNumbers *oid, OBJECT_IDENTIFIER_t *dst);

CRYPTONITE_EXPORT int pkix_get_key_id_from_spki(const SubjectPublicKeyInfo_t *spki, ByteArray **key_id);

#ifdef __cplusplus
}
#endif

#endif
