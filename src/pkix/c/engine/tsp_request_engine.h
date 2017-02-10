/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __TSP_REQUEST_ENGINE_H
#define __TSP_REQUEST_ENGINE_H

#include <stdbool.h>

#include "pkix_structs.h"
#include "oids.h"
#include "digest_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_tsp_req_signer_info_engine Генератор запиту мітки часу
 * @{
 */

/**
 * Генерує TSP запит.
 *
 * @param digest_aid алгоритм гешування
 * @param hash геш від повідомлення в le форматі
 * @param rnd ідентифікатор запиту
 * @param policy відповідь TSP (політика сертифікації)
 * @param cert_req вимога у відповіді сертифікату TSP
 * @param tsp_req запит TSP
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int etspreq_generate_from_hash(AlgorithmIdentifier_t *digest_aid, const ByteArray *hash,
                                                 const ByteArray *rnd, const OBJECT_IDENTIFIER_t *policy, bool cert_req, TimeStampReq_t **tsp_req);

/**
 * Генерує TSP запит.
 *
 * @param da адаптер гешування
 * @param msg TSP повідомлення
 * @param rnd ідентифікатор запиту
 * @param policy відповідь TSP (політика сертифікації)
 * @param cert_req вимога у відповіді сертифікату TSP
 * @param tsp_req запит TSP
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int etspreq_generate(const DigestAdapter *da, const ByteArray *msg, const ByteArray *rnd,
                                       OBJECT_IDENTIFIER_t *policy, bool cert_req, TimeStampReq_t **tsp_req);

CRYPTONITE_EXPORT int etspreq_generate_from_gost34311(const ByteArray *hash, const char *policy, bool cert_req,
                                                      TimeStampReq_t **tsp_req);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
