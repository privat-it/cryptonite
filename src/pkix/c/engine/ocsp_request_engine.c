/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ocsp_request_engine.h"

#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "cert.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "cryptonite_manager.h"
#include "ext.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/ocsp_request_engine.c"

struct OcspRequestEngine_st {
    const VerifyAdapter
    *root_va;           /**< Контекст перевірки пдпису кореневим сертифікатом */
    const VerifyAdapter
    *ocsp_va;           /**< Контекст перевірки підпису сертифікатом OCSP сервису */
    const SignAdapter           *requestor_sa;      /**< Адаптер підпису підписчика */
    DigestAlgorithmIdentifier_t
    *hash_aid;          /**< Алгоритм гешування для генерації ідентифікатора сертифікату */
    OCSPResponse_t              *ocsp_resp;         /**< Відповідь на запит */
    bool                         is_nonce_present;  /**< Прапорець наявності мітки */
    Request_t
    **reqs;              /**< Набір інформації про сертифікати, статуси яких запитуються */
    int
    reqs_cnt;          /**< Кількість сертифікатів, статуси яких запитуються */
    ByteArray                   *name_hash;         /**< Геш від імені рутового сертифікату */
    ByteArray
    *key_hash;          /**< Геш від відкритого ключа рутового сертифікату */
};

/**
 * Создает и инициализирует контекст .
 *
 * @param ctx указатель на создаваемый контекст
 * @param is_nonce_present флаг наличия метки
 * @param root_va ссылка на корневой адаптер проверки подписи
 * @param ocsp_va ссылка на адаптер проверки подписи OCSP сертификата
 * @param subject_sa ссылка на адаптер подписи субъекта, формирующего запрос
 * @param da адаптер хеширования
 *
 * @return код ошибки
 */
int eocspreq_alloc(bool is_nonce_present,
        const VerifyAdapter *root_va,
        const VerifyAdapter *ocsp_va,
        const SignAdapter *subject_sa,
        const DigestAdapter *da,
        OcspRequestEngine **ctx)
{
    int ret = RET_OK;

    Certificate_t *cert = NULL;
    OcspRequestEngine *engine = NULL;
    ByteArray *encoded = NULL;
    ByteArray *buffer = NULL;
    bool flag;
    bool has_cert;

    LOG_ENTRY();

    CHECK_PARAM(root_va != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(ctx != NULL);

    if (root_va->has_cert(root_va, &has_cert) == RET_OK && !has_cert) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_REQ_ADAPTER_HASNOT_CERT);
    }

    CALLOC_CHECKED(engine, sizeof(OcspRequestEngine));

    /* Сохранение адаптеров. */
    engine->root_va = root_va;
    engine->ocsp_va = ocsp_va;

    /* Принадлежность к OCSP сертификату. */
    if (ocsp_va) {
        DO(ocsp_va->get_cert(ocsp_va, &cert));
        DO(cert_is_ocsp_cert(cert, &flag));
        if (!flag) {
            SET_ERROR(RET_PKIX_OCSP_REQ_ADAPTER_ISNOT_OCSP);
        }

        if (RET_OK != cert_verify(cert, root_va)) {
            SET_ERROR(RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_OCSPISSUER);
        }

        ASN_FREE(&Certificate_desc, cert);
        cert = NULL;
    }

    if (subject_sa) {
        engine->requestor_sa = subject_sa;
        DO(subject_sa->get_cert(subject_sa, &cert));

        if (RET_OK != cert_verify(cert, root_va)) {
            SET_ERROR(RET_PKIX_OCSP_REQ_ROOTCERT_ISNOT_REQUESTORISSUER);
        }

        ASN_FREE(&Certificate_desc, cert);
        cert = NULL;
    }

    /* Идентификатор алгоритма хеширования. */
    DO(da->get_alg(da, &engine->hash_aid));

    /* Хеш имени и ключа. */
    DO(root_va->get_cert(root_va, &cert));

    DO(asn_encode_ba(&Name_desc, &cert->tbsCertificate.subject, &encoded));
    DO(da->update(da, encoded));
    DO(da->final(da, &engine->name_hash));

    DO(asn_BITSTRING2ba(&cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey, &buffer));
    DO(da->update(da, buffer));
    DO(da->final(da, &engine->key_hash));

    /* Считываем флаг наличия метки. */
    engine->is_nonce_present = is_nonce_present;

    /* Пустой список запросов. */
    engine->reqs = NULL;
    engine->reqs_cnt = 0;

    *ctx = engine;
    engine = NULL;

cleanup:

    ba_free(buffer);
    ba_free(encoded);
    ASN_FREE(&Certificate_desc, cert);
    eocspreq_free(engine);

    return ret;
}

/**
 * Очищает контекст .
 *
 * @param ctx контекст
 *
 * @return код ошибки
 */
void eocspreq_free(OcspRequestEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        Request_t **reqs = ctx->reqs;
        int cnt = ctx->reqs_cnt;

        while (reqs && cnt--) {
            ASN_FREE(&Request_desc, reqs[cnt]);
        }

        free(reqs);
        ASN_FREE(&DigestAlgorithmIdentifier_desc, ctx->hash_aid);
        ba_free(ctx->name_hash);
        ba_free(ctx->key_hash);

        memset(ctx, 0, sizeof(OcspRequestEngine));

        free(ctx);
    }
}

/**
 * Добавляет идентификатор сертификата для проверки статуса.
 *
 * @param ctx контекст
 * @param sn серийный номер проверяемого сертификата
 *
 * @return код ошибки
 */
int eocspreq_add_sn(OcspRequestEngine *ctx, const CertificateSerialNumber_t *cert_sn)
{
    int ret = RET_OK;

    CertID_t *id = NULL;
    OCTET_STRING_t *iss_name_hash = NULL;
    OCTET_STRING_t *iss_key_hash = NULL;
    Request_t *request = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert_sn != NULL);

    ASN_ALLOC(iss_name_hash);
    ASN_ALLOC(iss_key_hash);
    asn_ba2OCTSTRING(ctx->name_hash, iss_name_hash);
    asn_ba2OCTSTRING(ctx->key_hash, iss_key_hash);

    ASN_ALLOC(id);

    DO(asn_copy(&OBJECT_IDENTIFIER_desc, iss_name_hash, &id->issuerNameHash));
    DO(asn_copy(&OBJECT_IDENTIFIER_desc, iss_key_hash, &id->issuerKeyHash));
    DO(asn_copy(&AlgorithmIdentifier_desc, ctx->hash_aid, &id->hashAlgorithm));
    DO(asn_copy(&CertificateSerialNumber_desc, cert_sn, &id->serialNumber));

    REALLOC_CHECKED(ctx->reqs, (ctx->reqs_cnt + 1) * sizeof(*request), ctx->reqs);

    ASN_ALLOC(request);

    DO(asn_copy(&CertID_desc, id, &request->reqCert));

    ctx->reqs[ctx->reqs_cnt] = request;
    request = NULL;
    ctx->reqs_cnt++;

cleanup:

    ASN_FREE(&CertID_desc, id);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, iss_name_hash);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, iss_key_hash);
    ASN_FREE(&Request_desc, request);

    return ret;
}

/**
 * Добавляет идентификатор сертификата.
 *
 * @param ctx контекст
 * @param cert проверяемый сертификат
 *
 * @return код ошибки
 */
int eocspreq_add_cert(OcspRequestEngine *ctx, const Certificate_t *cert)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert != NULL);

    if (RET_OK != cert_verify(cert, ctx->root_va)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_VERIFY_FAILED);
    }
    DO(eocspreq_add_sn(ctx, &cert->tbsCertificate.serialNumber));
cleanup:
    return ret;
}

/**
 * Генерирует запрос для отправки OCSP сервису.
 *
 * @param ctx контекст
 * @param req указатель на создаваемый запрос
 * @param rnd случайные байты
 * @param rnd_len количество случайных байт
 *
 * @return код ошибки
 */
int eocspreq_generate(OcspRequestEngine *ctx, ByteArray *rnd, OCSPRequest_t **req_)
{
    int ret = RET_OK;

    TBSRequest_t *tbs_req = NULL;
    Certificate_t *req_cert = NULL;
    GeneralName_t *req_name = NULL;
    Certificates_t *certs = NULL;
    Certificate_t *ocsp_verify_cert = NULL;
    Certificate_t *root_verify_cert = NULL;
    Signature_t *sign = NULL;
    AlgorithmIdentifier_t *alg_id = NULL;
    BIT_STRING_t *sign_bs = NULL;
    OCSPRequest_t *ocsp_req = NULL;

    Request_t *req = NULL;
    Extension_t *ext = NULL;

    ByteArray *sign_bytes = NULL;
    ByteArray *data_bytes = NULL;

    int i;
    bool has_cert = false;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(req_ != NULL);

    if (!ctx->requestor_sa || (ctx->requestor_sa->has_cert(ctx->requestor_sa, &has_cert) == RET_OK && has_cert == false)) {
        LOG_ENTRY();
        ASN_ALLOC(tbs_req);

        for (i = 0; i < ctx->reqs_cnt; i++) {
            CHECK_NOT_NULL(req = asn_copy_with_alloc(&Request_desc, ctx->reqs[i]));
            DO(ASN_SEQUENCE_ADD(&tbs_req->requestList.list, req));
            req = NULL;
        }

        if (ctx->is_nonce_present) {
            if (!rnd) {
                LOG_ERROR();
                SET_ERROR(RET_INVALID_PARAM);
            }

            DO(ext_create_nonce(false, rnd, &ext));
            ASN_ALLOC(tbs_req->requestExtensions);
            DO(ASN_SEQUENCE_ADD(&tbs_req->requestExtensions->list, ext));
            ext = NULL;
        }

        ASN_ALLOC(ocsp_req);
        DO(asn_copy(&TBSRequest_desc, tbs_req, &ocsp_req->tbsRequest));

    } else {
        DO(ctx->requestor_sa->get_cert(ctx->requestor_sa, &req_cert));

        ASN_ALLOC(req_name);
        req_name->present = GeneralName_PR_directoryName;
        DO(asn_copy(&Name_desc, &req_cert->tbsCertificate.subject, &req_name->choice.directoryName));

        ASN_ALLOC(tbs_req);

        CHECK_NOT_NULL(tbs_req->requestorName = asn_copy_with_alloc(&GeneralName_desc, req_name));

        for (i = 0; i < ctx->reqs_cnt; i++) {
            CHECK_NOT_NULL(req = asn_copy_with_alloc(&Request_desc, ctx->reqs[i]));
            DO(ASN_SEQUENCE_ADD(&tbs_req->requestList.list, req));
            req = NULL;
        }

        if (ctx->is_nonce_present) {
            if (!rnd) {
                LOG_ERROR();
                SET_ERROR(RET_INVALID_PARAM);
            }

            DO(ext_create_nonce(false, rnd, &ext));
            ASN_ALLOC(tbs_req->requestExtensions);
            DO(ASN_SEQUENCE_ADD(&tbs_req->requestExtensions->list, ext));
            ext = NULL;
        }

        ASN_ALLOC(certs);

        DO(ASN_SEQUENCE_ADD(&certs->list, req_cert));
        req_cert = NULL;

        if (ctx->ocsp_va) {
            DO(ctx->ocsp_va->get_cert(ctx->ocsp_va, &ocsp_verify_cert));
            DO(ASN_SEQUENCE_ADD(&certs->list, ocsp_verify_cert));
            ocsp_verify_cert = NULL;
        }

        DO(ctx->root_va->get_cert(ctx->root_va, &root_verify_cert));

        DO(ASN_SEQUENCE_ADD(&certs->list, root_verify_cert));
        root_verify_cert = NULL;

        DO(ctx->requestor_sa->get_sign_alg(ctx->requestor_sa, &alg_id));
        DO(asn_encode_ba(&TBSRequest_desc, tbs_req, &data_bytes));

        ASN_ALLOC(sign_bs);
        DO(ctx->requestor_sa->sign_data(ctx->requestor_sa, data_bytes, &sign_bytes));
        DO(sign_ba_to_bs(sign_bytes, alg_id, sign_bs));

        ASN_ALLOC(sign);
        DO(asn_copy(&AlgorithmIdentifier_desc, alg_id, &sign->signatureAlgorithm));
        DO(asn_copy(&BIT_STRING_desc, sign_bs, &sign->signature));
        CHECK_NOT_NULL(sign->certs = asn_copy_with_alloc(&Certificates_desc, certs));

        ASN_ALLOC(ocsp_req);
        DO(asn_copy(&TBSRequest_desc, tbs_req, &ocsp_req->tbsRequest));
        CHECK_NOT_NULL(ocsp_req->optionalSignature = asn_copy_with_alloc(&Signature_desc, sign));
    }

    *req_ = ocsp_req;

cleanup:

    ASN_FREE(&TBSRequest_desc, tbs_req);
    ASN_FREE(&Certificate_desc, req_cert);
    ASN_FREE(&GeneralName_desc, req_name);
    ASN_FREE(&Certificates_desc, certs);
    ASN_FREE(&Certificate_desc, ocsp_verify_cert);
    ASN_FREE(&Certificate_desc, root_verify_cert);
    ASN_FREE(&Signature_desc, sign);
    ASN_FREE(&AlgorithmIdentifier_desc, alg_id);
    ASN_FREE(&BIT_STRING_desc, sign_bs);
    ASN_FREE(&Request_desc, req);
    ASN_FREE(&Extension_desc, ext);

    ba_free(sign_bytes);
    ba_free(data_bytes);

    if (ret != RET_OK) {
        ASN_FREE(&OCSPRequest_desc, ocsp_req);
    }

    return ret;
}

/**
 * Проверяет структуру ответа OCSP сервиса.
 *
 * @param ocsp_resp декодированный ответ
 * @param current_time текущее время
 * @param timeout максимальное время таймаута в минутах
 *
 * @return код ошибки
 *         RET_EOCSPRESP_NOT_SUCCESSFUL статус ответа отличный от SUCCESSFUL
 *         RET_EOCSPREQ_ADAPTER_ISNOT_OCSP в ответе не задан nextUpdate
 */
int eocspreq_validate_resp(const OCSPResponse_t *ocsp_resp, time_t current_time, int timeout)
{
    int ret = RET_OK;
    BasicOCSPResponse_t *basic_resp = NULL;
    ResponseData_t *resp_data = NULL;

    ByteArray *bresp_buff = NULL;

    time_t next_up;
    long ocsp_status;
    int _warning_code_ = RET_OK;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(ocsp_resp != NULL);

    DO(asn_INTEGER2long(&ocsp_resp->responseStatus, &ocsp_status));
    if (ocsp_status != OCSPResponseStatus_successful) {
        SET_ERROR(RET_PKIX_OCSP_RESP_NOT_SUCCESSFUL);
    }

    if (!pkix_check_oid_parent(&ocsp_resp->responseBytes->responseType,
            oids_get_oid_numbers_by_id(OID_BASIC_RESPONSE_ID))) {
        SET_ERROR(RET_PKIX_UNSUPPORTED_OID);
    }

    DO(asn_OCTSTRING2ba(&ocsp_resp->responseBytes->response, &bresp_buff));
    CHECK_NOT_NULL(basic_resp = asn_decode_ba_with_alloc(&BasicOCSPResponse_desc, bresp_buff));
    CHECK_NOT_NULL(resp_data = asn_copy_with_alloc(&ResponseData_desc, &basic_resp->tbsResponseData));

    if (timeout >= 0) {
        time_t external_time = asn_GT2time(&resp_data->producedAt, NULL, false);

        if (current_time > (external_time + timeout * 60)) {
            SET_ERROR(RET_PKIX_OCSP_RESP_TIMEOUT);
        }
    }

    /* Проверка актуальности ответов. */
    for (i = 0; i < resp_data->responses.list.count; i++) {
        SingleResponse_t *singl_resp = resp_data->responses.list.array[i];

        if (singl_resp->nextUpdate) {
            next_up = asn_GT2time(singl_resp->nextUpdate, NULL, false);

            /* Время следующего обновления наступило - неактуальная информация. */
            if (next_up < current_time) {
                SET_ERROR(RET_PKIX_OCSP_RESP_NEXT_UPDATE_TIMEOUT);
            }
        } else {
            _warning_code_ = RET_PKIX_OCSP_REQ_RESPONSE_NEXTUP_WARNING;
        }
    }

cleanup:

    ASN_FREE(&BasicOCSPResponse_desc, basic_resp);
    ASN_FREE(&ResponseData_desc, resp_data);
    ba_free(bresp_buff);

    return (ret == RET_OK) ? _warning_code_ : ret;
}

int eocspreq_generate_from_cert(const Certificate_t *root_cert, const Certificate_t *user_cert,
        OCSPRequest_t **ocsp_req)
{
    VerifyAdapter *root_va = NULL;
    DigestAdapter *da = NULL;
    OcspRequestEngine *eocsp_request = NULL;
    OCSPRequest_t *request = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = NULL;
    ByteArray *nonce = NULL;
    int ret = RET_OK;

    CHECK_PARAM(root_cert != NULL);
    CHECK_PARAM(user_cert != NULL);
    CHECK_PARAM(ocsp_req != NULL);

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    CHECK_NOT_NULL(nonce = ba_alloc_by_len(20));

    DO(ba_set(seed, 0xfa));
    CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
    DO(prng_next_bytes(prng, nonce));

    DO(digest_adapter_init_default(&da));
    DO(verify_adapter_init_by_cert(root_cert, &root_va));
    DO(eocspreq_alloc(true, root_va, NULL, NULL, da, &eocsp_request));
    DO(eocspreq_add_cert(eocsp_request, user_cert));
    DO(eocspreq_generate(eocsp_request, nonce, &request));

    *ocsp_req = request;
    request = NULL;

cleanup:

    ba_free(seed);
    ba_free(nonce);
    prng_free(prng);
    digest_adapter_free(da);
    verify_adapter_free(root_va);
    ASN_FREE(&OCSPRequest_desc, request);
    eocspreq_free(eocsp_request);

    return ret;
}
