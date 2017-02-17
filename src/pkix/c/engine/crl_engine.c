/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "crl_engine.h"

#include "exts.h"
#include "ext.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "asn1_utils.h"
#include "crl.h"
#include "cert.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/crl_engine.c"

struct CrlEngine_st {
    const SignAdapter     *sign_adapter;       /**< Адаптер выработки ЭЦП для CRL */
    const VerifyAdapter   *verify_adapter;     /**< Адаптер проверки ЭЦП для CRL */
    CertificateList_t
    *clist;              /**< Предыдущий CRL, используется для обновления списков */
    RevokedCertificates_t
    *rcs;                /**< Набор записей отозванных сертификатов */
    char                  *crl_template_name;  /**< Имя шаблона CRL */
    CRLType                type;               /**< Тип CRL */
    Extensions_t          *crl_extensions;
    char                  *crl_description;    /**< Опис CRL */
};

int ecrl_alloc(const CertificateList_t *crl,
        const SignAdapter *sa,
        const VerifyAdapter *va,
        const Extensions_t *crl_exts,
        const char *crl_templ_name,
        CRLType type,
        const char *crl_desc,
        CrlEngine **ctx)
{
    int ret = RET_OK;
    bool is_delta;
    bool flag;
    CrlEngine *crl_ctx = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(va != NULL);
    CHECK_PARAM(crl_templ_name != NULL);
    CHECK_PARAM(crl_desc != NULL);

    DO(sa->has_cert(sa, &flag));

    if (!flag) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_SA_NO_CERTIFICATE);
    }

    if (crl) {
        DO(crl_verify(crl, va));
    }

    size_t crl_templ_name_len = strlen(crl_templ_name) + 1;
    size_t crl_desc_len = strlen(crl_desc) + 1;

    CALLOC_CHECKED(crl_ctx, sizeof(CrlEngine));
    CALLOC_CHECKED(crl_ctx->crl_template_name, crl_templ_name_len);
    CALLOC_CHECKED(crl_ctx->crl_description, crl_desc_len);

    crl_ctx->sign_adapter = sa;
    crl_ctx->verify_adapter = va;

    crl_ctx->type = type;
    memcpy(crl_ctx->crl_template_name, crl_templ_name, crl_templ_name_len);
    memcpy(crl_ctx->crl_description, crl_desc, crl_desc_len);

    if (crl) {
        CHECK_NOT_NULL(crl_ctx->clist = asn_copy_with_alloc(&CertificateList_desc, crl));
    }

    if (crl_exts) {
        CHECK_NOT_NULL(crl_ctx->crl_extensions = asn_copy_with_alloc(&Extensions_desc, crl_exts));
    }

    if (crl) {
        DO(crl_is_delta(crl, &is_delta));

        if (is_delta && type == CRL_DELTA) {
            if (crl->tbsCertList.revokedCertificates) {
                CHECK_NOT_NULL(crl_ctx->rcs = asn_copy_with_alloc(&RevokedCertificates_desc, crl->tbsCertList.revokedCertificates));
            } else {
                crl_ctx->rcs = NULL;
            }
        }
    }

    *ctx = crl_ctx;

cleanup:

    if (ret != RET_OK) {
        ecrl_free(crl_ctx);
    }

    return ret;
}

void ecrl_free(CrlEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        free(ctx->crl_template_name);
        free(ctx->crl_description);

        ASN_FREE(&CertificateList_desc, ctx->clist);
        ASN_FREE(&RevokedCertificates_desc, ctx->rcs);
        ASN_FREE(&Extensions_desc, ctx->crl_extensions);

        free(ctx);
    }
}

int ecrl_get_template_name(const CrlEngine *ctx, char **crl_templ_name)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crl_templ_name != NULL);

    CALLOC_CHECKED(*crl_templ_name, strlen(ctx->crl_template_name) + 1);

    memcpy(*crl_templ_name, ctx->crl_template_name, strlen(ctx->crl_template_name) + 1);

cleanup:

    return ret;
}

int ecrl_get_type(const CrlEngine *ctx, CRLType *type)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(type != NULL);

    *type = ctx->type;

cleanup:

    return ret;
}

int ecrl_get_description(const CrlEngine *ctx, char **crl_desc)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crl_desc != NULL);

    CALLOC_CHECKED(*crl_desc, strlen(ctx->crl_description) + 1);

    memcpy(*crl_desc, ctx->crl_description, strlen(ctx->crl_description) + 1);

cleanup:

    return ret;
}

int ecrl_add_revoked_cert(CrlEngine *ctx, const Certificate_t *cert, CRLReason_t *reason, const time_t *inv_date)
{
    int ret = RET_OK;
    ByteArray *sn = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert != NULL);

    DO(cert_verify(cert, ctx->verify_adapter));
    DO(cert_get_sn(cert, &sn));
    DO(ecrl_add_revoked_cert_by_sn(ctx, sn, reason, inv_date));

cleanup:

    ba_free(sn);

    return ret;
}

int ecrl_add_revoked_cert_by_sn(CrlEngine *ctx,
        const ByteArray *cert_sn,
        CRLReason_t *reason,
        const time_t *inv_date)
{
    int ret = RET_OK;

    CertificateSerialNumber_t *csn = NULL;
    RevokedCertificate_t *rc = NULL;

    Extensions_t *crl_exts = NULL;
    Extension_t *crl_reason_ext = NULL;
    Extension_t *crl_inval_date_ext = NULL;
    PKIXTime_t *rev_date = NULL;
    UTCTime_t *revocation_date = NULL;

    time_t cur_date;

    LOG_ENTRY();

    time(&cur_date);

    CHECK_PARAM(ctx != NULL);

    if (reason) {
        DO(ext_create_crl_reason(false, reason, &crl_reason_ext));
    }

    if (inv_date) {
        DO(ext_create_invalidity_date(false, inv_date, &crl_inval_date_ext));
    }

    if (crl_reason_ext || crl_inval_date_ext) {
        ASN_ALLOC(crl_exts);
        if (crl_reason_ext) {
            DO(ASN_SET_ADD(&crl_exts->list, crl_reason_ext));
            crl_reason_ext = NULL;
        }
        if (crl_inval_date_ext) {
            DO(ASN_SET_ADD(&crl_exts->list, crl_inval_date_ext));
            crl_inval_date_ext = NULL;
        }
    }

    ASN_ALLOC(rev_date);
    rev_date->present = PKIXTime_PR_utcTime;
    revocation_date = asn_time2UT(NULL, localtime(&cur_date), true);

    DO(asn_copy(&UTCTime_desc, revocation_date, &rev_date->choice.utcTime));

    DO(asn_create_integer_from_ba(cert_sn, &csn));

    ASN_ALLOC(rc);
    DO(asn_copy(&CertificateSerialNumber_desc, csn,  &rc->userCertificate));
    DO(asn_copy(&PKIXTime_desc, rev_date, &rc->revocationDate));

    if (crl_exts) {
        CHECK_NOT_NULL(rc->crlEntryExtensions = asn_copy_with_alloc(&Extensions_desc, crl_exts));
    }

    if (!ctx->rcs) {
        ASN_ALLOC(ctx->rcs);
    }

    DO(ASN_SEQUENCE_ADD(&ctx->rcs->list, rc));
    rc = NULL;

cleanup:

    ASN_FREE(&UTCTime_desc, revocation_date);
    ASN_FREE(&CertificateSerialNumber_desc, csn);
    ASN_FREE(&RevokedCertificate_desc, rc);
    ASN_FREE(&Extensions_desc, crl_exts);
    ASN_FREE(&Extension_desc, crl_reason_ext);
    ASN_FREE(&Extension_desc, crl_inval_date_ext);
    ASN_FREE(&PKIXTime_desc, rev_date);

    return ret;
}

int ecrl_merge_delta(CrlEngine *ctx, const CertificateList_t *full)
{
    int ret = RET_OK;
    int i;

    RevokedCertificates_t *merged = NULL;
    RevokedCertificates_t *full_rcs = NULL;
    RevokedCertificate_t *rc = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(full != NULL);

    if (ctx->type != CRL_FULL) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CRL_CANT_MERGE);
    }

    DO(crl_verify(full, ctx->verify_adapter));

    CHECK_NOT_NULL(merged = asn_copy_with_alloc(&RevokedCertificates_desc, ctx->clist->tbsCertList.revokedCertificates));
    CHECK_NOT_NULL(full_rcs = asn_copy_with_alloc(&RevokedCertificates_desc, full->tbsCertList.revokedCertificates));

    for (i = 0; i < full_rcs->list.count; i++) {
        CHECK_NOT_NULL(rc = asn_copy_with_alloc(&RevokedCertificate_desc, full_rcs->list.array[i]));
        DO(ASN_SEQUENCE_ADD(&merged->list, rc));
        rc = NULL;
    }

    ASN_FREE(&RevokedCertificates_desc, ctx->rcs);
    ctx->rcs = merged;

cleanup:

    ASN_FREE(&RevokedCertificates_desc, full_rcs);
    ASN_FREE(&RevokedCertificate_desc, rc);

    if (RET_OK != ret) {
        ASN_FREE(&RevokedCertificates_desc, merged);
    }

    return ret;
}

/**
 * Генерирует CRL.
 *
 * @param ctx контекст выпуска CRL
 * @param this_update время текущего обновления
 * @param next_update время следующего обновления
 * @param crl выпущенный CRL
 *
 * @return код ошибки
 */
static int ecrl_generate_core(CrlEngine *ctx, time_t *this_update, time_t *next_update, CertificateList_t **crl)
{
    int ret = RET_OK;

    AlgorithmIdentifier_t *aid = NULL;
    Certificate_t *cert = NULL;
    TBSCertList_t *tbs_crl = NULL;
    CertificateList_t *certificate_list = NULL;

    UTCTime_t *tptr_this_update = NULL;
    UTCTime_t *tptr_next_update = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(this_update != NULL);
    CHECK_PARAM(next_update != NULL);
    CHECK_PARAM(crl != NULL);

    ASN_ALLOC(tbs_crl);

    tbs_crl->thisUpdate.present = PKIXTime_PR_utcTime;
    tptr_this_update = asn_time2UT(NULL, localtime(this_update), true);
    DO(asn_copy(&UTCTime_desc, tptr_this_update, &tbs_crl->thisUpdate.choice.utcTime));

    tbs_crl->nextUpdate.present = PKIXTime_PR_utcTime;
    tptr_next_update = asn_time2UT(NULL, localtime(next_update), true);
    DO(asn_copy(&UTCTime_desc, tptr_next_update, &tbs_crl->nextUpdate.choice.utcTime));

    DO(asn_create_integer_from_long(Version_v2, &tbs_crl->version));

    DO(ctx->sign_adapter->get_sign_alg(ctx->sign_adapter, &aid));
    DO(ctx->sign_adapter->get_cert(ctx->sign_adapter, &cert));

    DO(asn_copy(&Name_desc, &cert->tbsCertificate.subject, &tbs_crl->issuer));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &tbs_crl->signature));

    if (ctx->rcs) {
        CHECK_NOT_NULL(tbs_crl->revokedCertificates = asn_copy_with_alloc(&RevokedCertificates_desc, ctx->rcs));
    }

    if (ctx->crl_extensions) {
        CHECK_NOT_NULL(tbs_crl->crlExtensions = asn_copy_with_alloc(&Extensions_desc, ctx->crl_extensions));
    }
    CHECK_NOT_NULL(certificate_list = crl_alloc());

    DO(crl_init_by_adapter(certificate_list, tbs_crl, ctx->sign_adapter));

    *crl = certificate_list;
    certificate_list = NULL;

cleanup:

    ASN_FREE(&AlgorithmIdentifier_desc, aid);
    ASN_FREE(&Certificate_desc, cert);
    ASN_FREE(&TBSCertList_desc, tbs_crl);
    ASN_FREE(&UTCTime_desc, tptr_this_update);
    ASN_FREE(&UTCTime_desc, tptr_next_update);

    crl_free(certificate_list);

    return ret;
}

int ecrl_generate_diff_next_update(CrlEngine *ctx, time_t diff_next_update, CertificateList_t **crl)
{
    int ret = RET_OK;
    time_t cur_time;
    time_t next_time;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(diff_next_update > 0);
    CHECK_PARAM(crl != NULL);

    time(&cur_time);
    next_time = cur_time + diff_next_update;
    DO(ecrl_generate_core(ctx, &cur_time, &next_time, crl));

cleanup:

    return ret;
}

int ecrl_generate_next_update(CrlEngine *ctx, time_t *next_update, CertificateList_t **crl)
{
    int ret = RET_OK;
    time_t cur_time;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(next_update != NULL);
    CHECK_PARAM(crl != NULL);

    time(&cur_time);
    DO(ecrl_generate_core(ctx, &cur_time, next_update, crl));
cleanup:
    return ret;
}

int ecrl_generate(CrlEngine *ctx, CertificateList_t **crl)
{
    int ret = RET_OK;
    time_t next_time;
    time_t cur_time;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(ctx->clist != NULL);

    if (ctx->clist->tbsCertList.nextUpdate.present == PKIXTime_PR_utcTime) {
        next_time = asn_UT2time(&ctx->clist->tbsCertList.nextUpdate.choice.utcTime, NULL, false);
    } else if (ctx->clist->tbsCertList.nextUpdate.present == PKIXTime_PR_generalTime) {
        next_time = asn_GT2time(&ctx->clist->tbsCertList.nextUpdate.choice.generalTime, NULL, false);
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
    }

    if (next_time == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }

    time(&cur_time);
    if (cur_time == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }

    DO(ecrl_generate_core(ctx, &cur_time, &next_time, crl));
cleanup:
    return ret;
}
