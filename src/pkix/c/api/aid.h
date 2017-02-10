/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef SRC_PKIX_C_API_AID_H_
#define SRC_PKIX_C_API_AID_H_

#include "pkix_structs.h"
#include "byte_array.h"
#include "dstu4145.h"
#include "gost28147.h"
#include "oids.h"
#include "ecdsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Створює неініціалізований об'єкт.
 *
 * @return вказівник на створений об'єкт або NULL у випадку помилки
 */
CRYPTONITE_EXPORT AlgorithmIdentifier_t *aid_alloc(void);

/**
 * Вивільняє пам'ять, яку займає об'єкт.
 *
 * @param aid об'єкт, який видаляється, або NULL
 */
CRYPTONITE_EXPORT void aid_free(AlgorithmIdentifier_t *aid);

/**
 * Повертає байтове представлення в DER-кодуванні.
 * Виділена пам'ять потребує вивільнення.
 *
 * @param aid ідентифікатор параметрів алгоритму
 * @param out вказівник на пам'ять, що виділяється, яка містить DER-представлення
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_encode(const AlgorithmIdentifier_t *aid, ByteArray **out);

/**
 * Ініціалізує aid з DER-представлення.
 *
 * @param aid ідентифікатор параметрів алгоритму
 * @param in  буфер з байтами DER-кодування
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_decode(AlgorithmIdentifier_t *aid, const ByteArray *in);

/**
 * Ініціалізує AlgorithmIdentifier з об'єктного ідентифікатора алгоритму та параметрів.
 *
 * @param aid    ідентифікатор параметрів алгоритму
 * @param oid    об'єктний ідентифікатор алгоритму
 * @param td     тип параметрів
 * @param params параметри
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_init(AlgorithmIdentifier_t *aid, const OBJECT_IDENTIFIER_t *oid,
        const asn_TYPE_descriptor_t *td, const void *params);

/**
 * Ініціалізує AlgorithmIdentifier з об'єктного ідентифікатора алгоритму в int-ому представленні та без параметрів.
 *
 * @param aid     ідентифікатор параметрів алгоритму
 * @param oid     об'єктний ідентифікатор алгоритму в int-ому представленні
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_init_by_oid(AlgorithmIdentifier_t *aid, const OidNumbers *oid);

/**
 * Формує AID для гешування по алгоритму ГОСТ 34311.
 *
 * @param aid AID для гешування по алгоритму ГОСТ 34311
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_create_gost3411(AlgorithmIdentifier_t **aid);

/**
 * Формує AID для гешування по алгоритму ГОСТ 34311.
 * Параметри встановлюються в NULL.
 *
 * @param aid AID для гешування по алгоритму ГОСТ 34311
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_create_gost3411_with_null(AlgorithmIdentifier_t **aid);

/**
 * Формує AID для гешування по алгоритму ГОСТ 34311.
 * Параметри встановлюються в NULL.
 *
 * @param aid AID для гешування по алгоритму ГОСТ 34311
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_create_hmac_gost3411(AlgorithmIdentifier_t **aid);

/**
 * Формує AID для шифрування по алгоритму ГОСТ 28147.
 * Параметри встановлюються в NULL.
 *
 * @param aid AID для шифрування по алгоритму ГОСТ 28147
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_create_gost28147_wrap(AlgorithmIdentifier_t **aid);

CRYPTONITE_EXPORT int aid_create_gost28147_cfb(AlgorithmIdentifier_t **aid);

/**
 * Формує AID для виробки/перевірки підпису по алгоритму ДСТУ 4145.
 *
 * @param ec_params     контекст праметрів ДСТУ 4145
 * @param cipher_params котекст параметрів ГОСТ 28147
 * @param is_le         форма зберігання LE/BE
 * @param aid           AID виробки/перевірки підпису по алгоритму ДСТУ 4145
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_create_dstu4145(const Dstu4145Ctx *ec_params, const Gost28147Ctx *cipher_params, bool is_le,
        AlgorithmIdentifier_t **aid);

/**
 * Ініціалізує crypto параметри для ДСТУ 4145.
 *
 * @param aid ASN1 структура алгоритму
 * @param ctx буфер для crypto параметрів ДСТУ 4145
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int aid_get_dstu4145_params(const AlgorithmIdentifier_t *aid, Dstu4145Ctx **ctx);

CRYPTONITE_EXPORT int aid_create_ecdsa_pubkey(const EcdsaParamsId param, AlgorithmIdentifier_t **aid);

CRYPTONITE_EXPORT int aid_get_ecdsa_params(const AlgorithmIdentifier_t *aid, EcdsaCtx **ctx);

#ifdef __cplusplus
}
#endif

#endif
