/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef CRYPTONITE_PKI_CRYPTONITE_MANAGER_H
#define CRYPTONITE_PKI_CRYPTONITE_MANAGER_H

#include "dh_adapter.h"
#include "digest_adapter.h"
#include "cipher_adapter.h"
#include "sign_adapter.h"
#include "verify_adapter.h"

#include "dstu4145.h"
#include "ecdsa.h"
#include "gost28147.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Ініціалізує алгоритм гешування параметрами за замовчуванням.
 *
 * @param da адаптер гешування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int digest_adapter_init_default(DigestAdapter **da);

/**
 * Ініціалізує геш адаптер, використовуючи ідентифікатор алгоритму.
 *
 * @param aid ідентифікатор параметрів алгоритму
 * @param da геш адаптер
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int digest_adapter_init_by_aid(const AlgorithmIdentifier_t *aid, DigestAdapter **da);

/**
 * Ініціалізує геш адаптер, використовуючи Certificate.
 *
 * @param cert ASN1 стуктура Certificate
 * @param da геш адаптер
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int digest_adapter_init_by_cert(const Certificate_t *cert, DigestAdapter **da);

CRYPTONITE_EXPORT DigestAdapter *digest_adapter_copy_with_alloc(const DigestAdapter *da);

/**
 * Очищує контекст digest_adapter_t.
 *
 * @param da контекст
 */
CRYPTONITE_EXPORT void digest_adapter_free(DigestAdapter *da);

/**
 * Ініціалізує адаптер шифрування на шифрування, використовуючи сертифікат.
 *
 * @param alg_id алгоритм шифрування
 * @param ca буфер для адаптера шифрування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int cipher_adapter_init(const AlgorithmIdentifier_t *alg_id, CipherAdapter **ca);

CRYPTONITE_EXPORT CipherAdapter *cipher_adapter_copy_with_alloc(const CipherAdapter *ca);

/**
 * Очищує контекст cipher_adapter_t.
 *
 * @param ca контекст
 */
CRYPTONITE_EXPORT void cipher_adapter_free(CipherAdapter *ca);

/**
 * Ініціалізує генерацію підпису за допомогою суб'єкта відкритого ключа.
 *
 * @param priv_key      закритий ключ
 * @param signature_aid ідентифікатор алгоритму підпису
 * @param alg           параметри ключа
 * @param sa            буфер для адаптера генерації підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_adapter_init_by_aid(const ByteArray *priv_key, const AlgorithmIdentifier_t *signature_aid,
        const AlgorithmIdentifier_t *alg, SignAdapter **sa);

/**
 * Ініціалізує генерацію підпису за допомогою сертифіката.
 *
 * @param private_key закритий ключ
 * @param cert сертифікат
 * @param sa буфер для адаптера генерації підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int sign_adapter_init_by_cert(const ByteArray *private_key, const Certificate_t *cert,
        SignAdapter **sa);

CRYPTONITE_EXPORT SignAdapter *sign_adapter_copy_with_alloc(const SignAdapter *sa);

CRYPTONITE_EXPORT int sign_adapter_set_opt_level(SignAdapter *sa, OptLevelId opt_level);

/**
 * Очищує контекст sign_adapter_t.
 *
 * @param sa контекст
 */
CRYPTONITE_EXPORT void sign_adapter_free(SignAdapter *sa);

/**
 * Ініціалізує перевірку підпису за допомогою суб'єкта відкритого ключа.
 *
 * @param signature_aid алгоритм підпису
 * @param pkey суб'єкт відкритого ключа
 * @param va буфер для адаптера перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int verify_adapter_init_by_spki(const AlgorithmIdentifier_t *signature_aid,
        const SubjectPublicKeyInfo_t *pkey,
        VerifyAdapter **va);

/**
 * Ініціалізує перевірку підпису за допомогою сертифікату.
 *
 * @param cert сертифікат
 * @param va буфер для адаптера перевірки підпису
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int verify_adapter_init_by_cert(const Certificate_t *cert, VerifyAdapter **va);

CRYPTONITE_EXPORT VerifyAdapter *verify_adapter_copy_with_alloc(const VerifyAdapter *va);

CRYPTONITE_EXPORT int verify_adapter_set_opt_level(VerifyAdapter *va, OptLevelId opt_level);

/**
 * Очищує контекст verify_adapter_t.
 *
 * @param va контекст
 */
CRYPTONITE_EXPORT void verify_adapter_free(VerifyAdapter *va);

/**
 * Ініціалізує dh adapter.
 *
 * @param priv_key закритий ключ
 * @param aid      ASN1-структура алгоритму підпису
 * @param dha      буфер для dh адаптера
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int dh_adapter_init(const ByteArray *priv_key, const AlgorithmIdentifier_t *aid, DhAdapter **dha);

CRYPTONITE_EXPORT DhAdapter *dh_adapter_copy_with_alloc(const DhAdapter *dha);

/**
 * Очищує контекст dh adapter.
 *
 * @param dha контекст
 */
CRYPTONITE_EXPORT void dh_adapter_free(DhAdapter *dha);

CRYPTONITE_EXPORT int create_dstu4145_spki(const OBJECT_IDENTIFIER_t *signature_alg_oid, const Dstu4145Ctx *ec_params,
        const Gost28147Ctx *cipher_params, const ByteArray *pub_key, SubjectPublicKeyInfo_t **dstu_spki);

CRYPTONITE_EXPORT int create_ecdsa_spki(const OBJECT_IDENTIFIER_t *signature_alg_oid, const ANY_t *pub_key_params,
        const EcdsaCtx *ec_params, const ByteArray *pub_key, SubjectPublicKeyInfo_t **ecdsa_spki);

/**
 * Формує AID для шифрування по алгоритму ГОСТ 28147.
 * Підтримуються сертифікати з алгоритмом підпису ДСТУ 4145.
 *
 * @param prng          контекст PRNG
 * @param oid           алгоритм шифрування
 * @param cert_with_dke сертифікат с SBOX
 * @param aid_gost      AID для шифрування по алгоритму ГОСТ 28147
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int get_gost28147_aid(PrngCtx *prng, const OBJECT_IDENTIFIER_t *oid,
        const Certificate_t *cert_with_dke, AlgorithmIdentifier_t **aid_gost);

/**
 * Повертає ДКЕ.
 *
 * @param aid AID
 * @param dke ДКЕ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int get_gost28147_cipher_params(const AlgorithmIdentifier_t *aid, OCTET_STRING_t **dke);

CRYPTONITE_EXPORT int get_gost28147_params_by_os(const OCTET_STRING_t *sbox_os, Gost28147Ctx **params);

/**
 * Шифрує ключові дані ключем шифрування,
 * який отриманий на основі спільного секрету.
 *
 * @param dha         адаптер обчислення спільного секрету
 * @param pub_key     сертифікат видавця
 * @param session_key сесійний ключ
 * @param rnd_bytes   64-байтний масив випадкових чисел
 * @param wrapped_key зашифрований ключ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int wrap_session_key(const DhAdapter *dha, const ByteArray *pub_key,
        const ByteArray *session_key, const ByteArray *rnd_bytes, ByteArray **wrapped_key);

/**
 * Розшифровує ключові дані ключем шифрування,
 * який отриманий на основі спільного секрету.
 *
 * @param dha            адаптер обчислення спільного секрету
 * @param wrapped_key    закритий ключ
 * @param rnd_bytes      64-байтний масив випадкових чисел
 * @param issuer_pub_key відкритий ключ видавця
 * @param session_key    розшифрований ключ
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int unwrap_session_key(const DhAdapter *dha, const ByteArray *wrapped_key,
        const ByteArray *rnd_bytes, const ByteArray *issuer_pub_key, ByteArray **session_key);

#ifdef __cplusplus
}
#endif

#endif
