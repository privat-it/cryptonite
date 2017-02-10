/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "cert_engine.h"

#include "log_internal.h"
#include "asn1_utils.h"
#include "pkix_errors.h"
#include "cert.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/cert_engine.c"

static const long long TIME_LIMIT = 2524608000;

struct CertificateEngine_st {
    const SignAdapter   *sign_adapter;       /**< Адаптер выработки ЭЦП */
    const DigestAdapter *digest_adapter;     /**< Адаптер выработки хэша */
    bool
    is_self_signed;     /**< Флаг генерации самоподписанного сертификата */
};

int ecert_alloc(const SignAdapter *sa, const DigestAdapter *da, bool is_self_signed, CertificateEngine **ctx)
{
    int ret = RET_OK;
    CertificateEngine *cert_ctx = NULL;
    bool hash_cert = false;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(ctx != NULL);

    if (!is_self_signed && (sa->has_cert(sa, &hash_cert) == RET_OK) && (hash_cert == false)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_SA_NO_CERTIFICATE);
    }

    if (*ctx != NULL ) {
        ecert_free(*ctx);
    }

    CALLOC_CHECKED(cert_ctx, sizeof(CertificateEngine));

    cert_ctx->sign_adapter = sa;
    cert_ctx->digest_adapter = da;
    cert_ctx->is_self_signed = is_self_signed;

    *ctx = cert_ctx;

cleanup:

    if (ret != RET_OK) {
        ecert_free(cert_ctx);
    }

    return ret;
}

void ecert_free(CertificateEngine *ctx)
{
    LOG_ENTRY();

    free(ctx);
}

static int get_pkix_time(time_t utc_time, PKIXTime_t **pkix_time)
{
    struct tm tm_time;
    PKIXTime_t *pkix_time_ptr = NULL;
    GeneralizedTime_t *generalTime = NULL;
    UTCTime_t *utcTime = NULL;
    int ret = RET_OK;

    CHECK_PARAM(pkix_time != NULL);

    ASN_ALLOC(pkix_time_ptr);

    memcpy(&tm_time, localtime(&utc_time), sizeof(tm_time));

    if (utc_time >= TIME_LIMIT) {
        pkix_time_ptr->present = PKIXTime_PR_generalTime;
        generalTime = asn_time2GT(NULL, &tm_time, true);
        DO(asn_copy(&GeneralizedTime_desc, generalTime, &pkix_time_ptr->choice.generalTime));

    } else {
        pkix_time_ptr->present = PKIXTime_PR_utcTime;
        utcTime = asn_time2UT(NULL, &tm_time, true);
        DO(asn_copy(&UTCTime_desc, utcTime, &pkix_time_ptr->choice.utcTime));

    }

    *pkix_time = pkix_time_ptr;
    pkix_time_ptr = NULL;

cleanup:

    ASN_FREE(&UTCTime_desc, utcTime);
    ASN_FREE(&GeneralizedTime_desc, generalTime);
    ASN_FREE(&PKIXTime_desc, pkix_time_ptr);

    return ret;
}

int ecert_generate(const CertificateEngine *ctx,
        const CertificationRequest_t *req,
        int ver,
        const ByteArray *cert_sn,
        const time_t *not_before,
        const time_t *not_after,
        const Extensions_t *exts,
        Certificate_t **cert)
{
    int ret = RET_OK;

    TBSCertificate_t *tbs_cert = NULL;
    AlgorithmIdentifier_t *aid = NULL;

    Name_t *issuer = NULL;
    Name_t *subject = NULL;

    Validity_t *validity = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;

    Certificate_t *issuer_cert = NULL;
    PKIXTime_t *tptr_not_before = NULL;
    PKIXTime_t *tptr_not_after = NULL;
    Certificate_t *certificate = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(req != NULL);
    CHECK_PARAM(cert_sn != NULL);
    CHECK_PARAM(not_before != NULL);
    CHECK_PARAM(not_after != NULL);
    CHECK_PARAM(cert != NULL);

    /* �?нформация о сертификате. */
    ASN_ALLOC(tbs_cert);

    issuer = &tbs_cert->issuer;
    subject = &tbs_cert->subject;
    validity = &tbs_cert->validity;
    spki = &tbs_cert->subjectPublicKeyInfo;

    /* Версия сертификата. */
    DO(asn_create_integer_from_long(ver, &tbs_cert->version));

    /* Серийный номер. */
    DO(asn_ba2INTEGER(cert_sn, &tbs_cert->serialNumber));

    if (ctx->is_self_signed) {
        /* �?дентификатор алгоритма. */
        DO(asn_copy(&AlgorithmIdentifier_desc, &req->signatureAlgorithm, &tbs_cert->signature));

        /* �?мя подписывающей стороны. */
        DO(asn_copy(&Name_desc, &req->certificationRequestInfo.subject, issuer));

        /* �?мя владельца сертификата. */
        DO(asn_copy(&Name_desc, issuer, subject));

    } else {
        /* �?дентификатор алгоритма. */
        DO(ctx->sign_adapter->get_sign_alg(ctx->sign_adapter, &aid));
        DO(asn_copy(&AlgorithmIdentifier_desc, aid, &tbs_cert->signature));
        DO(ctx->sign_adapter->get_cert(ctx->sign_adapter, &issuer_cert));

        /* �?мя подписывающей стороны. */
        DO(asn_copy(&Name_desc, &issuer_cert->tbsCertificate.subject, issuer));

        /* �?мя владельца сертификата. */
        DO(asn_copy(&Name_desc, &req->certificationRequestInfo.subject, subject));
    }

    /* Поле “Time” зі значенням до 31 грудня 2049 року (включно) кодується у форматі “UTCTime”;
     * починаючи з 01 січня 2050 року - у форматі “GeneralizedTime”
     */
    DO(get_pkix_time(*not_before, &tptr_not_before));
    DO(get_pkix_time(*not_after, &tptr_not_after));

    DO(asn_copy(&PKIXTime_desc, tptr_not_before, &validity->notBefore));
    DO(asn_copy(&PKIXTime_desc, tptr_not_after, &validity->notAfter));

    /* �?нформация об открытом ключе владельца сертификата. */
    DO(asn_copy(&SubjectPublicKeyInfo_desc, &req->certificationRequestInfo.subjectPKInfo, spki));

    if (exts) {
        CHECK_NOT_NULL(tbs_cert->extensions = asn_copy_with_alloc(&Extensions_desc, exts));
    }

    /* Генерация и подпись сертификата. */
    CHECK_NOT_NULL(certificate = cert_alloc());

    DO(cert_init_by_adapter(certificate, tbs_cert, ctx->sign_adapter));

    *cert = certificate;
    certificate = NULL;

cleanup:

    ASN_FREE(&PKIXTime_desc, tptr_not_before);
    ASN_FREE(&PKIXTime_desc, tptr_not_after);
    ASN_FREE(&TBSCertificate_desc, tbs_cert);
    ASN_FREE(&AlgorithmIdentifier_desc, aid);

    cert_free(issuer_cert);
    cert_free(certificate);

    return ret;
}
