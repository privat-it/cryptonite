/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

/*
 * Модуль реалізує роботу із запитом мітки часу (TimeStampReq, RFC 3161).
 * Надає створення/звільнення, ASN.1 кодування/декодування та доступ до полів
 * запиту: відбиток повідомлення (messageImprint), політика TSA, nonce (у т.ч.
 * його генерація), ознака запиту сертифіката (certReq) та версія.
 */

#include <time.h>
#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "pkix_utils.h"
#include "log_internal.h"
#include "tsp_request.h"
#include "pkix_macros_internal.h"


#undef FILE_MARKER
#define FILE_MARKER "pki/api/tsp_request.c"

/* Виділяє пам'ять під порожній об'єкт запиту мітки часу. */
TimeStampReq_t *tsreq_alloc(void)
{
    TimeStampReq_t *tsreq = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(tsreq);

cleanup:

    return tsreq;
}

/* Звільняє об'єкт запиту мітки часу. */
void tsreq_free(TimeStampReq_t *tsreq)
{
    LOG_ENTRY();

    if (tsreq) {
        ASN_FREE(&TimeStampReq_desc, tsreq);
    }
}

/* Кодує запит мітки часу у DER-подання. */
int tsreq_encode(const TimeStampReq_t *tsreq, ByteArray **out)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&TimeStampReq_desc, tsreq, out));
cleanup:
    return ret;
}

/* Декодує запит мітки часу з DER-подання; попередній вміст очищується. */
int tsreq_decode(TimeStampReq_t *tsreq, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&TimeStampReq_desc, tsreq);

    DO(asn_decode_ba(&TimeStampReq_desc, tsreq, in));

cleanup:
    return ret;
}

/* Повертає копію відбитка повідомлення (messageImprint). */
int tsreq_get_message(const TimeStampReq_t *tsreq, MessageImprint_t **mess_impr)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(mess_impr != NULL);
    CHECK_PARAM(*mess_impr == NULL);

    CHECK_NOT_NULL(*mess_impr = asn_copy_with_alloc(&MessageImprint_desc, &tsreq->messageImprint));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&MessageImprint_desc, *mess_impr);
        *mess_impr = NULL;
    }

    return ret;
}

/* Встановлює відбиток повідомлення (messageImprint) запиту. */
int tsreq_set_message(TimeStampReq_t *tsreq, const MessageImprint_t *mess_impr)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(mess_impr != NULL);

    ASN_FREE_CONTENT_STATIC(&MessageImprint_desc, &tsreq->messageImprint);
    DO(asn_copy(&MessageImprint_desc, mess_impr, &tsreq->messageImprint));

cleanup:

    return ret;
}

/* Повертає копію запитаної політики TSA; помилка, якщо політику не задано. */
int tsreq_get_policy(const TimeStampReq_t *tsreq, OBJECT_IDENTIFIER_t **req_policy)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(req_policy != NULL);
    CHECK_PARAM(*req_policy == NULL);

    if (!tsreq->reqPolicy) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_TSP_REQ_NO_REQ_POLICY);
    }

    CHECK_NOT_NULL(*req_policy = asn_copy_with_alloc(&TSAPolicyId_desc, tsreq->reqPolicy));

cleanup:

    return ret;
}

/* Встановлює запитану політику TSA. */
int tsreq_set_policy(TimeStampReq_t *tsreq, const OBJECT_IDENTIFIER_t *req_policy)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(req_policy != NULL);

    ASN_FREE_CONTENT_PTR(&TSAPolicyId_desc, tsreq->reqPolicy);
    if (tsreq->reqPolicy) {
        DO(asn_copy(&TSAPolicyId_desc, req_policy, tsreq->reqPolicy));
    } else {
        CHECK_NOT_NULL(tsreq->reqPolicy = asn_copy_with_alloc(&TSAPolicyId_desc, req_policy));
    }

cleanup:

    return ret;
}

/* Повертає копію nonce запиту; помилка, якщо nonce не задано. */
int tsreq_get_nonce(const TimeStampReq_t *tsreq, INTEGER_t **nonce)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(nonce != NULL);
    CHECK_PARAM(*nonce == NULL);

    if (!tsreq->nonce) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_TSP_REQ_NO_NONCE);
    }

    CHECK_NOT_NULL(*nonce = asn_copy_with_alloc(&INTEGER_desc, tsreq->nonce));

cleanup:

    return ret;
}

/* Встановлює nonce запиту. */
int tsreq_set_nonce(TimeStampReq_t *tsreq, const INTEGER_t *nonce)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(nonce != NULL);

    ASN_FREE(&INTEGER_desc, tsreq->nonce);
    CHECK_NOT_NULL(tsreq->nonce = asn_copy_with_alloc(&INTEGER_desc, nonce));

cleanup:

    return ret;
}

/* Генерує nonce запиту на основі поточного часу та лічильника тактів. */
int tsreq_generate_nonce(TimeStampReq_t *tsreq)
{
    int ret = RET_OK;
    time_t date;
    clock_t ticks;
    uint8_t cur_time[sizeof(time_t) + sizeof(clock_t)];

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);

    date = time(NULL);
    ticks = clock();
    memcpy(cur_time, &date, sizeof(date));
    memcpy(cur_time + sizeof(date), &ticks, sizeof(ticks));

    ASN_FREE(&INTEGER_desc, tsreq->nonce);
    tsreq->nonce = NULL;
    DO(asn_create_integer(cur_time, sizeof(cur_time), &tsreq->nonce));

cleanup:

    return ret;
}

/* Повертає ознаку certReq (чи потрібно включати сертифікат TSA у відповідь). */
int tsreq_get_cert_req(const TimeStampReq_t *tsreq, bool *cert_req)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(cert_req != NULL);

    if (!tsreq->certReq) {
        *cert_req = false;
    } else {
        *cert_req = *(int *)tsreq->certReq;
    }

cleanup:

    return ret;
}

/* Встановлює ознаку certReq (поле додається лише для true). */
int tsreq_set_cert_req(TimeStampReq_t *tsreq, bool cert_req)
{
    int ret = RET_OK;
    BOOLEAN_t cr = cert_req;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);

    ASN_FREE(&BOOLEAN_desc, tsreq->certReq);
    tsreq->certReq = NULL;
    if (cert_req) {
        CHECK_NOT_NULL(tsreq->certReq = asn_copy_with_alloc(&BOOLEAN_desc, &cr));
    }

cleanup:

    return ret;
}

/* Повертає копію версії запиту мітки часу. */
int tsreq_get_version(const TimeStampReq_t *tsreq, INTEGER_t **version)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsreq != NULL);
    CHECK_PARAM(version != NULL);
    CHECK_PARAM(*version == NULL);

    CHECK_NOT_NULL(*version = asn_copy_with_alloc(&INTEGER_desc, &tsreq->version));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&INTEGER_desc, *version);
        *version = NULL;
    }

    return ret;
}
