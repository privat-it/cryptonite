/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkix_structs.h"
#include "ocsp_response_engine.h"

#include "log_internal.h"
#include "asn1_utils.h"
#include "pkix_errors.h"
#include "verify_adapter.h"
#include "cert.h"
#include "crl.h"
#include "pkix_utils.h"
#include "ocsp_request.h"
#include "exts.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/ocsp_response_engine.c"

struct OcspResponseEngine_st {
    const VerifyAdapter
    *root_va;                  /**< Контекст проверки подписи корневым сертификатом */
    const SignAdapter
    *ocsp_sa;                  /**< Контекст формирования подписи OCSP сервисом */
    ResponderID_t        *responder;                /**< �?дентификатор ответчика OCSP */
    bool                  is_sign_required;         /**< Флаг проверки подписи в запросе */
    bool
    is_nextup_required;       /**< Флаг указания времени следующего обновления */
    bool
    is_crlreason_required;    /**< Флаг указания причины отзыва сертификата */
    CertificateLists_t   *crls;                     /**< Списки отозванных сертификатов */
    ByteArray            *name_hash;                /**< Хэш от имени корневого сертификата */
    ByteArray
    *key_hash;                 /**< Хэш от открытого ключа корневого сертификата */
};

/**
 * Проверяет, является ли сертификат OCSP.
 *
 * @param cert сертификат
 * @param is_ocsp true - сертификат OCSP, иначе false
 * @return код ошибки
 */
static int is_ocsp_cert(const Certificate_t *cert, bool *is_ocsp)
{
    int ret = RET_OK;
    Extensions_t *exts = NULL;
    ExtendedKeyUsage_t *ext_key_usage = NULL;
    ByteArray *bytes = NULL;

    int i;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(is_ocsp != NULL);

    ASN_ALLOC(ext_key_usage);

    ASN_ALLOC(exts);
    DO(asn_copy(&Extensions_desc, cert->tbsCertificate.extensions, exts));

    for (i = 0; i < exts->list.count; i++) {
        Extension_t *ext = exts->list.array[i];

        if (pkix_check_oid_parent(&ext->extnID, oids_get_oid_numbers_by_id(OID_EXT_KEY_USAGE_EXTENSION_ID))) {
            ba_free(bytes);
            bytes = NULL;

            DO(asn_OCTSTRING2ba(&ext->extnValue, &bytes));
            DO(asn_decode_ba(&ExtendedKeyUsage_desc, ext_key_usage, bytes));

            if (ext_key_usage->list.count == 1) {
                if (pkix_check_oid_parent(ext_key_usage->list.array[0], oids_get_oid_numbers_by_id(OID_OCSP_KEY_PURPOSE_ID))) {
                    *is_ocsp = true;
                    goto cleanup;
                }
            }
        }
    }

    *is_ocsp = false;

cleanup:

    ASN_FREE(&Extensions_desc, exts);
    ASN_FREE(&ExtendedKeyUsage_desc, ext_key_usage);
    ba_free(bytes);

    return ret;
}

/**
 * Проверяет подписи сертификатов и списков отозванных сертификатов.
 * Доинициализирует контекст engine'а проверочными адаптерами.
 *
 * @param ctx контекст генератора ответа
 * @param root_va адаптер проверки подписи корневого сертификата
 * @param ocsp_sa адаптер подписи ответа OCSP
 *
 * @return true - подписи верны, иначе false
 */
static int verify_input_data(OcspResponseEngine *ctx,
        const VerifyAdapter *root_va,
        const SignAdapter *ocsp_sa)
{
    int ret = RET_OK;
    Certificate_t *certificate = NULL;
    int i;
    bool root_va_cert;
    bool ocsp_sa_cert;
    bool is_ocsp;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(root_va != NULL);
    CHECK_PARAM(ocsp_sa != NULL);

    DO(root_va->has_cert(root_va, &root_va_cert));
    if (!root_va_cert) {
        SET_ERROR(RET_PKIX_VA_NO_CERTIFICATE);
    }

    DO(ocsp_sa->has_cert(ocsp_sa, &ocsp_sa_cert));
    if (!ocsp_sa_cert) {
        SET_ERROR(RET_PKIX_SA_NO_CERTIFICATE);
    }

    DO(ocsp_sa->get_cert(ocsp_sa, &certificate));
    DO(cert_verify(certificate, root_va));
    DO(is_ocsp_cert(certificate, &is_ocsp));
    if (!is_ocsp) {
        SET_ERROR(RET_PKIX_SA_NOT_OCSP_CERT);
    }

    ctx->root_va = root_va;
    ctx->ocsp_sa = ocsp_sa;

    for (i = 0; i < ctx->crls->list.count; i++) {
        DO(crl_verify(ctx->crls->list.array[i], root_va));
    }

cleanup:

    cert_free(certificate);

    return ret;
}

/**
 * Генерирует идентификаторы имени и открытого ключа издателя сертификатов.
 * Эталонное значение используется при сравнении полей в CertID в запросе OCSP.
 *
 * @param ctx контекст генератора ответа
 * @param da адаптер хеширования для вычисления идентификатора
 * @param issuer_cert сертификат издателя, для вычисления идентификатора
 *
 * @return код ошибки
 */
static int generate_issuer_ids(OcspResponseEngine *ctx,
        const DigestAdapter *da,
        const Certificate_t *issuer_cert)
{
    int ret = RET_OK;
    ByteArray *pub_key_bytes = NULL;
    ByteArray *subject_bytes = NULL;

    LOG_ENTRY();

    CHECK_PARAM(da != NULL);
    CHECK_PARAM(issuer_cert != NULL);

    DO(asn_BITSTRING2ba(&issuer_cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &pub_key_bytes));
    DO(asn_encode_ba(&Name_desc, &issuer_cert->tbsCertificate.subject, &subject_bytes));

    ba_free(ctx->name_hash);
    ctx->name_hash = NULL;
    ba_free(ctx->key_hash);
    ctx->key_hash = NULL;

    DO(da->update(da, pub_key_bytes));
    DO(da->final(da, &ctx->key_hash));

    DO(da->update(da, subject_bytes));
    DO(da->final(da, &ctx->name_hash));

cleanup:

    ba_free(pub_key_bytes);
    ba_free(subject_bytes);

    return ret;
}

/**
 * Генерирует идентификатор ответчика OCSP.
 *
 * @param ctx контекст генератора ответа
 * @param da  адаптер хеширования, если в шаблоне указан идентификатор
 *            открытого ключа сертификата.
 * @param id_ type тип идентификатора
 *
 * @return код ошибки
 */
static int generate_responder_id(OcspResponseEngine *ctx, const DigestAdapter *da, ResponderIdType id_type)
{
    int ret = RET_OK;
    OCTET_STRING_t *key_os = NULL;
    Certificate_t *certificate = NULL;

    ByteArray *pk_bytes = NULL;
    ByteArray *digest = NULL;

    LOG_ENTRY();

    ASN_FREE(&ResponderID_desc, ctx->responder);
    ctx->responder = NULL;
    ASN_ALLOC(ctx->responder);

    DO(ctx->ocsp_sa->get_cert(ctx->ocsp_sa, &certificate));

    switch (id_type) {
    case OCSP_RESPONSE_BY_HASH_KEY:
        DO(asn_BITSTRING2ba(&certificate->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &pk_bytes));
        DO(da->update(da, pk_bytes));
        DO(da->final(da, &digest));
        DO(asn_create_octstring_from_ba(digest, &key_os));

        ctx->responder->present = ResponderID_PR_byKey;
        DO(asn_copy(&OCTET_STRING_desc, key_os, &ctx->responder->choice.byKey));
        break;

    case OCSP_RESPONSE_BY_NAME:
        ctx->responder->present = ResponderID_PR_byName;
        DO(asn_copy(&Name_desc, &certificate->tbsCertificate.subject, &ctx->responder->choice.byName));
        break;

    default:
        SET_ERROR(RET_PKIX_UNSUPPORTED_RESPONDER_ID);
    }

cleanup:

    ASN_FREE(&Certificate_desc, certificate);
    ASN_FREE(&OCTET_STRING_desc, key_os);

    ba_free(digest);
    ba_free(pk_bytes);

    return ret;
}

/**
 * Валидирует запрос на соответствие правилам формирования.
 *
 * @param ctx контекст генератора ответа
 * @param req запрос статуса сертификата
 * @param va  адаптер для проверки подписи запроса
 *
 * @return код ошибки или исключение
 */
static int validate_req(const OcspResponseEngine *ctx, const OCSPRequest_t *req, const VerifyAdapter *va)
{
    int ret = RET_OK;

    LOG_ENTRY();

    if (!ctx->is_sign_required) {
        return RET_OK;
    }

    if (!req->optionalSignature) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_REQ_NO_SIGN);
    }

    if (!req->tbsRequest.requestorName) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_REQ_NO_REQUESTOR_NAME);
    }

    ret = ocspreq_verify(req, va);

    if (ret == RET_PKIX_VERIFY_FAILED) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_REQ_VERIFY_FAILED);
    } else if (ret != RET_OK) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_INTERNAL_ERROR_EXCEPTION);
    }

cleanup:

    return ret;
}

/**
 * Валидирует идентификатор сертификата. Сравнивает идентификаторы имени и открытого
 * ключа издателя проверяемого сертификата с эталонными значениями.
 *
 * @param ctx контекст генератора ответа
 * @param id идентификатор сертификата, по которому проверяется статус
 *
 * @return код ошибки или исключение
 */
static int validate_cert_id(const OcspResponseEngine *ctx, const CertID_t *id)
{
    int ret = RET_OK;
    ByteArray *name_hash = NULL;
    ByteArray *key_hash = NULL;

    LOG_ENTRY();

    DO(asn_OCTSTRING2ba(&id->issuerNameHash, &name_hash));
    DO(asn_OCTSTRING2ba(&id->issuerKeyHash, &key_hash));

    if (ba_cmp(name_hash, ctx->name_hash)) {
        SET_ERROR(RET_PKIX_OCSP_RESP_INVALID_NAME_HASH);
    }

    if (ba_cmp(key_hash, ctx->key_hash)) {
        SET_ERROR(RET_PKIX_OCSP_RESP_INVALID_KEY_HASH);
    }

cleanup:

    ba_free(name_hash);
    ba_free(key_hash);

    return ret;
}

/**
 * Производит поиск информации об отозванном сертификата в списке установленых
 * списков отозванных сертификатов и возвращает последний статус сертификата
 * из списка CRL.
 *
 * @param ctx контекст генератора ответа
 * @param sn  серийный номер отозванного сертификата
 *
 * @return информация об отозванном сертификате или null - если сертификат
 * не находится ни в одном из списков.
 */
static RevokedCertificate_t *get_revocation(OcspResponseEngine *ctx, const CertificateSerialNumber_t *sn)
{
    int i;
    int ret = RET_OK;
    RevokedCertificate_t *founded_revocation = NULL;
    RevokedCertificate_t *freshest_revocation = NULL;
    CertificateList_t *last_founded_crl = NULL;

    LOG_ENTRY();

    for (i = 0; i < ctx->crls->list.count; i++) {
        CertificateList_t *c_list = ctx->crls->list.array[i];

        ASN_FREE(&RevokedCertificate_desc, founded_revocation);
        founded_revocation = NULL;
        ret = crl_get_cert_info_by_sn(c_list, sn, &founded_revocation);
        if (ret == RET_OK) {
            if (freshest_revocation) {
                const PKIXTime_t *previous = &last_founded_crl->tbsCertList.thisUpdate;
                const PKIXTime_t *current = &c_list->tbsCertList.thisUpdate;

                time_t t_prev =
                        previous->present == PKIXTime_PR_utcTime ?
                        asn_UT2time(&previous->choice.utcTime, NULL, false) :
                        asn_GT2time(&previous->choice.generalTime, NULL, false);

                time_t t_curr =
                        current->present == PKIXTime_PR_utcTime ?
                        asn_UT2time(&current->choice.utcTime, NULL, false) :
                        asn_GT2time(&current->choice.generalTime, NULL, false);

                if (t_curr > t_prev) {
                    CHECK_NOT_NULL(freshest_revocation = asn_copy_with_alloc(&RevokedCertificate_desc, founded_revocation));
                    last_founded_crl = c_list;
                }

            } else {
                CHECK_NOT_NULL(freshest_revocation = asn_copy_with_alloc(&RevokedCertificate_desc, founded_revocation));
                last_founded_crl = c_list;
            }
        } else  if (ret == RET_PKIX_OBJ_NOT_FOUND) {
            ret = RET_OK;
        } else {
            DO(ret);
        }
    }

cleanup:

    ASN_FREE(&RevokedCertificate_desc, founded_revocation);

    return RET_OK == ret ? freshest_revocation : NULL ;
}

/**
 * Возвращает причину отзыва сертификата.
 *
 * @param revocation информация об отозванном сертификате
 *
 * @return причина отзыва
 */
static CRLReason_t *get_reason(const RevokedCertificate_t *revocation)
{
    CRLReason_t *reason = NULL;
    ByteArray *os_crl_reason = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(revocation);

    DO(exts_get_ext_value_by_oid(revocation->crlEntryExtensions, oids_get_oid_numbers_by_id(OID_CE_CRL_REASON_ID),
            &os_crl_reason));
    CHECK_NOT_NULL(reason = asn_decode_ba_with_alloc(&CRLReason_desc, os_crl_reason));

cleanup:

    ba_free(os_crl_reason);

    return reason;
}

/**
 * Конвертирует время из ASN1 структуры в time_t.
 *
 * @return время или -1, в случае ошибки
 */
static time_t asn_time_2_time_t(const PKIXTime_t *asn_time)
{
    LOG_ENTRY();

    switch (asn_time->present) {

    case PKIXTime_PR_utcTime:
        return asn_UT2time(&asn_time->choice.utcTime, NULL, false);

    case PKIXTime_PR_generalTime:
        return asn_GT2time(&asn_time->choice.generalTime, NULL, false);

    default:
        return (time_t) - 1;
    }
}

/**
 * Возвращает ближайшее время обновления из списка CRL-сертификатов,
 * отталкиваясь от переданного текущего времени.
 *
 * @param ctx контекст генератора ответа
 * @param current_time текущее время
 *
 * @return ASN1-структура GeneralizedTime или NULL, в случае ошибки
 */
static GeneralizedTime_t *get_nearest_update(const OcspResponseEngine *ctx, time_t current_time)
{
    int i;
    int ret = RET_OK;
    TBSCertList_t *tbs_c_list = NULL;
    PKIXTime_t *next_update = NULL;
    PKIXTime_t *crl_next = NULL;

    time_t tt_crl_next;
    time_t tt_next_update;
    time_t tt_return;

    LOG_ENTRY();

    for (i = 0; i < ctx->crls->list.count; i++) {
        ASN_FREE(&TBSCertList_desc, tbs_c_list);
        tbs_c_list = NULL;
        DO(crl_get_tbs(ctx->crls->list.array[i], &tbs_c_list));

        if (next_update == NULL) {
            CHECK_NOT_NULL(next_update = asn_copy_with_alloc(&PKIXTime_desc, &tbs_c_list->nextUpdate));
            continue;
        }

        ASN_FREE(&PKIXTime_desc, crl_next);
        CHECK_NOT_NULL(crl_next = asn_copy_with_alloc(&PKIXTime_desc, &tbs_c_list->nextUpdate));

        tt_crl_next = asn_time_2_time_t(crl_next);
        tt_next_update = asn_time_2_time_t(next_update);

        if (tt_crl_next < tt_next_update && tt_crl_next > current_time) {
            ASN_FREE(&PKIXTime_desc, next_update);
            CHECK_NOT_NULL(next_update = asn_copy_with_alloc(&PKIXTime_desc, crl_next));
        }
    }

    ret = next_update ? (tt_return = asn_time_2_time_t(next_update), RET_OK) : !RET_OK;

cleanup:

    ASN_FREE(&TBSCertList_desc, tbs_c_list);
    ASN_FREE(&PKIXTime_desc, next_update);
    ASN_FREE(&PKIXTime_desc, crl_next);

    return (RET_OK == ret) ? asn_time2GT(NULL, localtime(&tt_return), true) : NULL ;
}

/**
 * Возвращает последнее время обновления из списка CRL-сертификатов.
 *
 * @param ctx контекст генератора ответа
 *
 * @return ASN1-структура GeneralizedTime или NULL, в случае ошибки
 */
static GeneralizedTime_t *get_last_update(const OcspResponseEngine *ctx)
{
    int ret = RET_OK;
    int i;
    TBSCertList_t *tbs_c_list = NULL;

    PKIXTime_t *last_update = NULL;
    PKIXTime_t *crl_update = NULL;

    time_t tt_last_update = 0;
    time_t tt_crl_update = 0;
    GeneralizedTime_t *res = NULL;

    LOG_ENTRY();

    for (i = 0; i < ctx->crls->list.count; i++) {
        ASN_FREE(&TBSCertList_desc, tbs_c_list);
        tbs_c_list = NULL;
        DO(crl_get_tbs(ctx->crls->list.array[i], &tbs_c_list));

        if (!last_update) {
            CHECK_NOT_NULL(last_update = asn_copy_with_alloc(&PKIXTime_desc, &tbs_c_list->thisUpdate));
            tt_last_update = asn_time_2_time_t(last_update);
            continue;
        }

        ASN_FREE(&PKIXTime_desc, crl_update);
        CHECK_NOT_NULL(crl_update = asn_copy_with_alloc(&PKIXTime_desc, &tbs_c_list->thisUpdate));
        tt_crl_update = asn_time_2_time_t(crl_update);

        if (tt_crl_update > tt_last_update) {
            ASN_FREE(&PKIXTime_desc, last_update);
            CHECK_NOT_NULL(last_update = asn_copy_with_alloc(&PKIXTime_desc, &tbs_c_list->thisUpdate));
            tt_last_update = tt_crl_update;
        }
    }

    if (last_update) {
        res = asn_time2GT(NULL, localtime(&tt_last_update), true);
    } else {
        res = NULL;
    }

cleanup:

    ASN_FREE(&TBSCertList_desc, tbs_c_list);
    ASN_FREE(&PKIXTime_desc, last_update);
    ASN_FREE(&PKIXTime_desc, crl_update);

    return res;
}

/**
 * Обрабатывает одиночный запрос на проверку статуса сертификата.
 *
 * @param ctx контекст генератора ответа
 * @param req запрос на проверку статуса
 * @param current_time текущее время
 * @param sr указатель на создаваемый ответ со статусом сертификата
 *
 * @return код ошибки или исключение
 */
static int get_resp(OcspResponseEngine *ctx, const Request_t *req, time_t current_time, SingleResponse_t **sr)
{
    int ret = RET_OK;

    RevokedCertificate_t *revocation = NULL;
    CertStatus_t *status = NULL;
    CRLReason_t *reason = NULL;
    RevokedInfo_t *rev_info = NULL;
    GeneralizedTime_t *next_update = NULL;
    GeneralizedTime_t *last_update = NULL;
    Extensions_t *single_exts = NULL;

    PKIXTime_t *rev_time = NULL;
    GeneralizedTime_t *rev_date = NULL;
    SingleResponse_t *single_response = NULL;

    time_t tt_utc_time;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(req != NULL);
    CHECK_PARAM(sr != NULL);

    if (req->singleRequestExtensions) {

        /* Расширения запроса не поддерживаются. */
        LOG_ERROR();
        SET_ERROR(RET_OCSP_REQ_NOSINGLE_REQ_EXTS);
    }

    DO(validate_cert_id(ctx, &req->reqCert));

    revocation = get_revocation(ctx, &req->reqCert.serialNumber);

    if (revocation == NULL) {

        ASN_ALLOC(status);
        status->present = CertStatus_PR_good;
        status->choice.good = true;

    } else {

        reason = get_reason(revocation);
        if (ctx->is_crlreason_required && !reason) {
            SET_ERROR(RET_PKIX_OCSP_RESP_NO_CRL_REASON);
        }

        CHECK_NOT_NULL(rev_time = asn_copy_with_alloc(&PKIXTime_desc, &revocation->revocationDate));

        switch (rev_time->present) {

        case PKIXTime_PR_utcTime:
            tt_utc_time = asn_UT2time(&rev_time->choice.utcTime, NULL, false);
            CHECK_NOT_NULL(rev_date = asn_time2GT(NULL, localtime(&tt_utc_time), true));
            break;

        case PKIXTime_PR_generalTime:
            CHECK_NOT_NULL(rev_date = asn_copy_with_alloc(&GeneralizedTime_desc, &rev_time->choice.generalTime));
            break;

        default:
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
        }

        ASN_ALLOC(rev_info);
        DO(asn_copy(&GeneralizedTime_desc, rev_date, &rev_info->revocationTime));
        CHECK_NOT_NULL(rev_info->revocationReason = asn_copy_with_alloc(&CRLReason_desc, reason));

        ASN_ALLOC(status);
        status->present = CertStatus_PR_revoked;
        DO(asn_copy(&RevokedInfo_desc, rev_info, &status->choice.revoked));
    }

    next_update = get_nearest_update(ctx, current_time);
    if (ctx->is_nextup_required && !next_update) {
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_NEXT_UPDATE);
    }

    last_update = get_last_update(ctx);
    if (!last_update) {
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_LAST_UPDATE);
    }

    if (revocation && revocation->crlEntryExtensions) {
        CHECK_NOT_NULL(single_exts = asn_copy_with_alloc(&Extensions_desc, revocation->crlEntryExtensions));
    }

    ASN_ALLOC(single_response);

    DO(asn_copy(&CertID_desc, &req->reqCert, &single_response->certID));
    DO(asn_copy(&CertStatus_desc, status, &single_response->certStatus));
    DO(asn_copy(&GeneralizedTime_desc, last_update, &single_response->thisUpdate));

    CHECK_NOT_NULL(single_response->nextUpdate = asn_copy_with_alloc(&GeneralizedTime_desc, next_update));

    if (single_exts) {
        CHECK_NOT_NULL(single_response->singleExtensions = asn_copy_with_alloc(&Extensions_desc, single_exts));
    }

    *sr = single_response;

cleanup:

    ASN_FREE(&RevokedCertificate_desc, revocation);
    ASN_FREE(&CertStatus_desc, status);
    ASN_FREE(&CRLReason_desc, reason);
    ASN_FREE(&RevokedInfo_desc, rev_info);
    ASN_FREE(&GeneralizedTime_desc, next_update);
    ASN_FREE(&GeneralizedTime_desc, last_update);
    ASN_FREE(&Extensions_desc, single_exts);
    ASN_FREE(&PKIXTime_desc, rev_time);
    ASN_FREE(&GeneralizedTime_desc, rev_date);

    if (RET_OK != ret) {
        ASN_FREE(&SingleResponse_desc, single_response);
    }

    return ret;
}

/**
 * Последовательная обработка запросов.
 *
 * @param ctx контекст генератора ответа
 * @param tbs_req cписок запросов
 * @param current_time текущее время
 * @param resp_data указатель на создаваемый список ответов
 *
 * @return код ошибки или исключение
 */
static int process_reqs(OcspResponseEngine *ctx,
        const TBSRequest_t *tbs_req,
        time_t current_time,
        ResponseData_t **resp_data)
{
    int ret = RET_OK;
    SingleResponse_t *sr = NULL;
    ResponseData_t *data = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(tbs_req != NULL);
    CHECK_PARAM(resp_data != NULL);

    ASN_ALLOC(data);

    for (i = 0; i < tbs_req->requestList.list.count; i++) {
        DO(get_resp(ctx, tbs_req->requestList.list.array[i], current_time, &sr));
        DO(ASN_SEQUENCE_ADD(&data->responses.list, sr));
        sr = NULL;
    }

    *resp_data = data;

cleanup:

    ASN_FREE(&SingleResponse_desc, sr);

    if (RET_OK != ret) {
        ASN_FREE(&ResponseData_desc, data);
    }

    return ret;
}

/**
 * Процесс проверки статуса сертификата.
 *
 * @param ctx контекст генератора ответа
 * @param req запрос на проверку статуса
 * @param req_va адаптер для проверки подписи
 * @param current_time текущее время
 * @param resp_bytes указатель на создаваемый ответ на запрос
 *
 * @return код ошибки или исключение
 */
static int try_check_status(OcspResponseEngine *ctx,
        const OCSPRequest_t *req,
        const VerifyAdapter *req_va,
        time_t current_time,
        ResponseBytes_t **resp_bytes)
{
    int ret = RET_OK;

    ResponseData_t *resps = NULL;
    Extension_t *nonce = NULL;
    Extensions_t *exts = NULL;

    GeneralizedTime_t *produced_at = NULL;
    BasicOCSPResponse_t *bocsp = NULL;
    AlgorithmIdentifier_t *sign_aid = NULL;

    Certificate_t *ocsp_sign_cert = NULL;
    Certificate_t *root_verify_cert = NULL;
    Certificates_t *chain = NULL;
    ResponseBytes_t *resp = NULL;

    ByteArray *sign = NULL;
    ByteArray *data_bytes = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(req != NULL);
    CHECK_PARAM(req_va != NULL);
    CHECK_PARAM(resp_bytes != NULL);

    DO(validate_req(ctx, req, req_va));
    DO(process_reqs(ctx, &req->tbsRequest, current_time, &resps));

    ASN_ALLOC(exts);
    ret = exts_get_ext_by_oid(req->tbsRequest.requestExtensions, oids_get_oid_numbers_by_id(OID_NONCE_EXTENSION_ID),
            &nonce);
    if (ret == RET_OK) {
        DO(ASN_SEQUENCE_ADD(exts, nonce));
        nonce = NULL;
    } else if (ret != RET_PKIX_EXT_NOT_FOUND) {
        DO(ret);
    }

    CHECK_NOT_NULL(resps->responseExtensions = asn_copy_with_alloc(&Extensions_desc, exts));
    CHECK_NOT_NULL(produced_at = asn_time2GT(NULL, localtime(&current_time), true));

    DO(asn_copy(&ResponderID_desc, ctx->responder, &resps->responderID));
    DO(asn_copy(&GeneralizedTime_desc, produced_at, &resps->producedAt));

    ASN_ALLOC(bocsp);

    DO(ctx->ocsp_sa->get_sign_alg(ctx->ocsp_sa, &sign_aid));
    DO(asn_copy(&AlgorithmIdentifier_desc, sign_aid, &bocsp->signatureAlgorithm));
    DO(asn_copy(&ResponseData_desc, resps, &bocsp->tbsResponseData));

    DO(asn_encode_ba(&ResponseData_desc, resps, &data_bytes));
    DO(ctx->ocsp_sa->sign_data(ctx->ocsp_sa, data_bytes, &sign));
    DO(sign_ba_to_bs(sign, sign_aid, &bocsp->signature));

    ASN_ALLOC(chain);

    DO(ctx->ocsp_sa->get_cert(ctx->ocsp_sa, &ocsp_sign_cert));
    DO(ASN_SEQUENCE_ADD(chain, ocsp_sign_cert));
    ocsp_sign_cert = NULL;
    DO(ctx->root_va->get_cert(ctx->root_va, &root_verify_cert));
    DO(ASN_SEQUENCE_ADD(chain, root_verify_cert));
    root_verify_cert = NULL;

    CHECK_NOT_NULL(bocsp->certs = asn_copy_with_alloc(&Certificates_desc, chain));

    ba_free(data_bytes);
    data_bytes = NULL;
    DO(asn_encode_ba(&BasicOCSPResponse_desc, bocsp, &data_bytes));

    ASN_ALLOC(resp);

    DO(asn_ba2OCTSTRING(data_bytes, &resp->response));
    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_BASIC_RESPONSE_ID), &resp->responseType));

    *resp_bytes = resp;

cleanup:

    ASN_FREE(&ResponseData_desc, resps);
    ASN_FREE(&Extension_desc, nonce);
    ASN_FREE(&Extensions_desc, exts);
    ASN_FREE(&GeneralizedTime_desc, produced_at);
    ASN_FREE(&BasicOCSPResponse_desc, bocsp);
    ASN_FREE(&AlgorithmIdentifier_desc, sign_aid);
    ASN_FREE(&Certificate_desc, ocsp_sign_cert);
    ASN_FREE(&Certificate_desc, root_verify_cert);
    ASN_FREE(&Certificates_desc, chain);

    ba_free(sign);
    ba_free(data_bytes);

    if (RET_OK != ret) {
        ASN_FREE(&ResponseBytes_desc, resp);
    }

    return ret;
}

/**
 * Проверяет списки отозванных сертификатов на валидность. Проверяет подписи списков.
 * Обновляет списки в контексте генератора ответов.
 *
 * @param ctx контекст генератора ответа
 * @param crls списки отозванных сертификатов
 *
 * @return код ошибки
 */
static int verify_crls(OcspResponseEngine *ctx, const CertificateLists_t *crls)
{
    int i;
    int ret = RET_OK;

    LOG_ENTRY();
    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crls != NULL);

    if (crls->list.count == 0) {
        return RET_PKIX_VERIFY_FAILED;
    }

    for (i = 0; i < crls->list.count; i++) {
        if (crl_verify(crls->list.array[i], ctx->root_va)) {
            return RET_PKIX_VERIFY_FAILED;
        }
    }

cleanup:

    return ret;
}

int eocspresp_alloc(const VerifyAdapter *root_va,
        const SignAdapter *ocsp_sign,
        const CertificateLists_t *crls,
        const DigestAdapter *da,
        bool next_up_req,
        bool crl_reason_req,
        ResponderIdType id_type,
        OcspResponseEngine **ctx)
{
    int ret = RET_OK;
    Certificate_t *root_cert = NULL;
    OcspResponseEngine *engine = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(root_va != NULL);
    CHECK_PARAM(ocsp_sign != NULL);
    CHECK_PARAM(crls != NULL);
    CHECK_PARAM(da != NULL);

    CALLOC_CHECKED(engine,  sizeof(OcspResponseEngine));

    CHECK_NOT_NULL(engine->crls = asn_copy_with_alloc(&CertificateLists_desc, crls));

    DO(verify_input_data(engine, root_va, ocsp_sign));

    DO(root_va->get_cert(root_va, &root_cert));

    engine->is_nextup_required = next_up_req;
    engine->is_crlreason_required = crl_reason_req;

    DO(generate_issuer_ids(engine, da, root_cert));
    DO(generate_responder_id(engine, da, id_type));

    *ctx = engine;

cleanup:

    ASN_FREE(&Certificate_desc, root_cert);
    if (RET_OK != ret) {
        eocspresp_free(engine);
    }

    return ret;
}

void eocspresp_set_sign_required(OcspResponseEngine *ctx, bool sign_required)
{
    LOG_ENTRY();

    if (ctx) {
        ctx->is_sign_required = sign_required;
    }
}

int eocspresp_set_crls(OcspResponseEngine *ctx, const CertificateLists_t *crls)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crls != NULL);

    DO(verify_crls(ctx, crls));

    if (ctx->crls) {
        ASN_FREE(&CertificateLists_desc, ctx->crls);
        ctx->crls = NULL;
    }
    CHECK_NOT_NULL(ctx->crls = asn_copy_with_alloc(&CertificateLists_desc, crls));


cleanup:

    return ret;
}

int eocspresp_generate(OcspResponseEngine *ctx,
        const OCSPRequest_t *req,
        const VerifyAdapter *req_va,
        time_t current_time,
        OCSPResponse_t **resp)
{
    int ret = RET_OK;
    OCSPResponseStatus_t resp_copy;
    ResponseBytes_t *resp_bytes = NULL;
    OCSPResponse_t *ocsp_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(req != NULL);
    CHECK_PARAM(req_va != NULL);
    CHECK_PARAM(resp != NULL);

    memset(&resp_copy, 0, sizeof(resp_copy));
    ret = try_check_status(ctx, req, req_va, current_time, &resp_bytes);

    switch (ret) {

    case RET_OK:
        DO(asn_long2INTEGER(&resp_copy, OCSPResponseStatus_successful));
        break;

    case RET_PKIX_MALFORMED_REQUEST_EXCEPTION:
    case RET_PKIX_OCSP_REQ_NO_REQUESTOR_NAME:
    case RET_PKIX_OCSP_REQ_VERIFY_FAILED:
        DO(asn_long2INTEGER(&resp_copy, OCSPResponseStatus_malformedRequest));
        break;

    case RET_PKIX_INTERNAL_ERROR_EXCEPTION:
    case RET_PKIX_OCSP_RESP_NO_CRL_REASON:
        DO(asn_long2INTEGER(&resp_copy, OCSPResponseStatus_internalError));
        break;

    case RET_PKIX_SIG_REQUIRED_EXCEPTION:
    case RET_PKIX_OCSP_REQ_NO_SIGN:
        DO(asn_long2INTEGER(&resp_copy, OCSPResponseStatus_sigRequired));
        break;

    default:
        SET_ERROR(ret);
    }

    ASN_ALLOC(ocsp_response);

    DO(asn_copy(&OCSPResponseStatus_desc, &resp_copy, &ocsp_response->responseStatus));

    if (resp_bytes) {
        CHECK_NOT_NULL(ocsp_response->responseBytes = asn_copy_with_alloc(&ResponseBytes_desc, resp_bytes));
    } else {
        ocsp_response->responseBytes = NULL;
    }

    *resp = ocsp_response;

cleanup:

    ASN_FREE_CONTENT_STATIC(&OCSPResponseStatus_desc, &resp_copy);
    ASN_FREE(&ResponseBytes_desc, resp_bytes);

    if (RET_OK != ret) {
        ASN_FREE(&OCSPResponse_desc, ocsp_response);
    }

    return ret;
}

int eocspresp_form_malformed_req(OCSPResponse_t **resp)
{
    int ret = RET_OK;
    OCSPResponseStatus_t *resp_copy = NULL;
    OCSPResponse_t *ocsp_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(resp);
    ASN_ALLOC(resp_copy);

    DO(asn_long2INTEGER(resp_copy, OCSPResponseStatus_malformedRequest));

    ASN_ALLOC(ocsp_response);

    DO(asn_copy(&OCSPResponseStatus_desc, resp_copy, &ocsp_response->responseStatus));

    *resp = ocsp_response;

cleanup:

    if (RET_OK != ret) {
        ASN_FREE(&OCSPResponse_desc, ocsp_response);
    }
    ASN_FREE(&OCSPResponseStatus_desc, resp_copy);

    return ret;
}

int eocspresp_form_internal_error(OCSPResponse_t **resp)
{
    int ret = RET_OK;
    OCSPResponseStatus_t *resp_copy = NULL;
    OCSPResponse_t *ocsp_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(resp);

    ASN_ALLOC(resp_copy);
    DO(asn_long2INTEGER(resp_copy, OCSPResponseStatus_internalError));

    ASN_ALLOC(ocsp_response);

    DO(asn_copy(&OCSPResponseStatus_desc, resp_copy, &ocsp_response->responseStatus));

    *resp = ocsp_response;

cleanup:

    if (RET_OK != ret) {
        ASN_FREE(&OCSPResponse_desc, ocsp_response);
    }
    ASN_FREE(&OCSPResponseStatus_desc, resp_copy);

    return ret;
}

int eocspresp_form_try_later(OCSPResponse_t **resp)
{
    int ret = RET_OK;
    OCSPResponseStatus_t *resp_copy = NULL;
    OCSPResponse_t *ocsp_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(resp);

    ASN_ALLOC(resp_copy);
    DO(asn_long2INTEGER(resp_copy, OCSPResponseStatus_tryLater));

    ASN_ALLOC(ocsp_response);

    DO(asn_copy(&OCSPResponseStatus_desc, resp_copy, &ocsp_response->responseStatus));

    *resp = ocsp_response;

cleanup:

    if (RET_OK != ret) {
        ASN_FREE(&OCSPResponse_desc, ocsp_response);
    }
    ASN_FREE(&OCSPResponseStatus_desc, resp_copy);

    return ret;
}

int eocspresp_form_unauthorized(OCSPResponse_t **resp)
{
    int ret = RET_OK;
    OCSPResponse_t *ocsp_response = NULL;
    OCSPResponseStatus_t resp_copy;

    LOG_ENTRY();

    CHECK_PARAM(resp);

    memset(&resp_copy, 0, sizeof(resp_copy));
    DO(asn_long2INTEGER(&resp_copy, OCSPResponseStatus_unauthorized));

    ASN_ALLOC(ocsp_response);

    DO(asn_copy(&OCSPResponseStatus_desc, &resp_copy, &ocsp_response->responseStatus));

    *resp = ocsp_response;

cleanup:

    if (RET_OK != ret) {
        ASN_FREE(&OCSPResponse_desc, *resp);
    }
    free(resp_copy.buf);
    return ret;
}

void eocspresp_free(OcspResponseEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        ASN_FREE(&ResponderID_desc, ctx->responder);
        ASN_FREE(&CertificateLists_desc, ctx->crls);
        ba_free(ctx->name_hash);
        ba_free(ctx->key_hash);
        free(ctx);
    }
}
