/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef __TSP_RESPONSE_ENGINE_H__
#define __TSP_RESPONSE_ENGINE_H__

#include <time.h>

#include "pkix_structs.h"
#include "adapters_map.h"
#include "digest_adapter.h"
#include "sign_adapter.h"
#include "signed_data_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup cryptos_pkix_tsp_resp_engine Генератор відповіді на запит мітки часу
 * @{
 */

/**
 * Генерує TSP відповідь.
 *
 * @param tsp_map адаптери гешування та підпису для різних політик формування TSP відповіді
 * @param tsp_req TSP запит
 * @param sn серійний номер
 * @param tsp_digest_aids алгоритми гешування, які підтримуються
 * @param current_time поточний час
 * @param tsp_resp відповідь TSP
 *
 * @return код помилки
 */
CRYPTONITE_EXPORT int etspresp_generate(const AdaptersMap *tsp_map, const ByteArray *tsp_req, const INTEGER_t *sn,
                                        const DigestAlgorithmIdentifiers_t *tsp_digest_aids, const time_t *current_time, TimeStampResp_t **tsp_resp);

/** @} */

#ifdef __cplusplus
}
#endif

#endif
