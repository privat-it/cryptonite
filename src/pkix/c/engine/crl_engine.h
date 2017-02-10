/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __CRL_ENGINE_H__
#define __CRL_ENGINE_H__

#include <time.h>

#include "pkix_structs.h"
#include "sign_adapter.h"
#include "verify_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_crl_engine Генератор cписку відкликаних сертифікатів
 * @{
 */

typedef enum CRLType {
    CRL_DELTA = 0,
    CRL_FULL = 1
} CRLType;

typedef struct CrlEngine_st CrlEngine;

/**
 * Ініціалізує контекст випуску CRL.
 *
 * @param crl попередній CRL, використовується для оновлення списків
 * @param sa посилання на ініціалізований адаптер підпису для CRL
 * @param va посилання на ініціалізований адаптер перевірки підпису для CRL
 * @param crl_exts набір розширень CRL, який випускаєтся
 * @param crl_templ_name ім'я шаблона CRL
 * @param type тип CRL
 * @param crl_desc опис CRL
 * @param ctx контекст випуску CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_alloc(const CertificateList_t *crl, const SignAdapter *sa, const VerifyAdapter *va,
                                 const Extensions_t *crl_exts, const char *crl_templ_name, CRLType type, const char *crl_desc, CrlEngine **ctx);

/**
 * Очищує контекст випуску CRL.
 *
 * @param ctx контекст випуску CRL
 */
CRYPTONITE_EXPORT void ecrl_free(CrlEngine *ctx);

/**
 * Повертає ідентифікатор шаблона.
 *
 * @param ctx контекст випуску CRL
 * @param crl_templ_name ідентифікатор шаблону
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_get_template_name(const CrlEngine *ctx, char **crl_templ_name);

/**
 * Повертає тип CRL.
 *
 * @param ctx контекст випуску CRL
 * @param type тип CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_get_type(const CrlEngine *ctx, CRLType *type);

/**
 * Повертає опис шаблону.
 *
 * @param ctx контекст випуску CRL
 * @param crl_desc опис шаблону
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_get_description(const CrlEngine *ctx, char **crl_desc);

/**
 * Додає запис відкликаного сертифікату в список. Якщо движок проініціалізований
 * попереднім CRL, то його список доповнюється, інакше - створюєтья новий список. Перевіряється
 * підпис сертифікату, який додається. Видавець у сертифікату, який додається, повинен
 * збігатися з видавцем CRL.
 *
 * @param ctx контекст выпуску CRL
 * @param cert відкликаний сертифікат
 * @param reason причина відклику або null
 * @param inv_date час компрометації ключа або null
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_add_revoked_cert(CrlEngine *ctx, const Certificate_t *cert, CRLReason_t *reason,
                                            const time_t *inv_date);

/**
 * Додає запис відкликаного сертифікату. Якщо движок проініціалізований
 * попереднім CRL, то його список доповнюється, інакше - створюєтья новий список.
 *
 * @param ctx контекст випуску CRL
 * @param cert_sn серійний номер сертифікату, який додається
 * @param reason причина відклику або null
 * @param inv_date час компрометації ключа або null
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_add_revoked_cert_by_sn(CrlEngine *ctx, const ByteArray *cert_sn, CRLReason_t *reason,
                                                  const time_t *inv_date);

/**
 * Зливає повний або частковий CRL та оновлює повний CRL.
 * Для злиття движок повинен бути проініціалізований попередніми частковими CRL.
 *
 * @param ctx контекст випуску CRL
 * @param full попередній повний CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_merge_delta(CrlEngine *ctx, const CertificateList_t *full);

/**
 * Генерує CRL.
 *
 * @param ctx контекст випуску CRL
 * @param diff_next_update кількість мілісекунд до наступного оновлення
 * @param crl випущений CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_generate_diff_next_update(CrlEngine *ctx, time_t diff_next_update, CertificateList_t **crl);

/**
 * Генерує CRL.
 *
 * @param ctx контекст випуску CRL
 * @param next_update час наступного оновлення
 * @param crl випущений CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_generate_next_update(CrlEngine *ctx, time_t *next_update, CertificateList_t **crl);

/**
 * Генерує CRL.
 *
 * @param ctx контекст випуску CRL
 * @param crl випущений CRL
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int ecrl_generate(CrlEngine *ctx, CertificateList_t **crl);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
