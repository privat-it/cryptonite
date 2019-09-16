/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "signed_data_engine.h"

#include "pkix_utils.h"
#include "pkix_macros_internal.h"
#include "asn1_utils.h"
#include "oids.h"
#include "log_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/signed_data_engine.c"

typedef struct SignerInfoEngineArr_st {
    SignerInfoEngine **sinfo;
    int size;
} SignerInfoEngineArr;

struct SignedDataEngine_st {
    SignerInfoEngineArr sinfos;
    CertificateSet_t *certs;
    RevocationInfoChoices_t *revoc_choices;
    EncapsulatedContentInfo_t *info;
    OCTET_STRING_t *encap_data;
    OCTET_STRING_t *encap_hash_data;
};

int esigned_data_alloc(SignerInfoEngine *signer, SignedDataEngine **ctx)
{
    int ret = RET_OK;
    SignedDataEngine *engine = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(signer != NULL);

    CALLOC_CHECKED(engine, sizeof(SignedDataEngine));
    CALLOC_CHECKED(engine->sinfos.sinfo, sizeof(SignerInfoEngine *));

    engine->sinfos.sinfo[0] = signer;
    engine->sinfos.size = 1;

    *ctx = engine;

cleanup:

    if (ret != RET_OK) {
        esigned_data_free(engine);
    }

    return ret;
}

void esigned_data_free(SignedDataEngine *ctx)
{
    int i;

    LOG_ENTRY();

    if (!ctx) {
        return;
    }

    for (i = 0; i < ctx->sinfos.size; i++) {
        esigner_info_free(ctx->sinfos.sinfo[i]);
    }

    LOG_FREE(ctx->sinfos.sinfo);

    ASN_FREE(&CertificateSet_desc, ctx->certs);
    ASN_FREE(&RevocationInfoChoices_desc, ctx->revoc_choices);
    ASN_FREE(&EncapsulatedContentInfo_desc, ctx->info);
    ASN_FREE(&OCTET_STRING_desc, ctx->encap_data);
    ASN_FREE(&OCTET_STRING_desc, ctx->encap_hash_data);

    LOG_FREE(ctx);
}

int esigned_data_set_data(SignedDataEngine *ctx,
        const OidNumbers *oid,
        const ByteArray *data,
        bool is_internal_data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(data != NULL);

    if (ctx->info) {
        ASN_FREE(&EncapsulatedContentInfo_desc, ctx->info);
        ctx->info = NULL;
    }

    ASN_ALLOC(ctx->info);
    ctx->encap_data = NULL;

    DO(pkix_set_oid(oid, &ctx->info->eContentType));
    DO(asn_create_octstring_from_ba(data, &ctx->encap_data));

    if (is_internal_data) {
        DO(asn_create_octstring_from_ba(data, &ctx->info->eContent));
    } else {
        ctx->info->eContent = NULL;
    }

cleanup:

    return ret;
}

int esigned_data_set_hash_data(SignedDataEngine *ctx,
        const OidNumbers *oid,
        const ByteArray *hash)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(hash != NULL);

    if (ctx->info) {
        ASN_FREE(&EncapsulatedContentInfo_desc, ctx->info);
        ctx->info = NULL;
    }

    ASN_ALLOC(ctx->info);
    ctx->encap_data = NULL;

    DO(pkix_set_oid(oid, &ctx->info->eContentType));
    DO(asn_create_octstring_from_ba(hash, &ctx->encap_hash_data));

cleanup:

    return ret;
}

int esigned_data_set_content_info(SignedDataEngine *ctx, const EncapsulatedContentInfo_t *info)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(info != NULL);

    if (ctx->info) {
        ASN_FREE_CONTENT_PTR(&EncapsulatedContentInfo_desc, ctx->info);
    } else {
        ASN_ALLOC(ctx->info);
    }
    DO(asn_copy(&EncapsulatedContentInfo_desc, info, ctx->info));
cleanup:
    return ret;
}

int esigned_data_add_cert(SignedDataEngine *ctx, const Certificate_t *cert)
{
    int ret = RET_OK;
    CertificateChoices_t *cert_choices = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert != NULL);

    ASN_ALLOC(cert_choices);

    cert_choices->present = CertificateChoices_PR_certificate;
    DO(asn_copy(&Certificate_desc, cert, &cert_choices->choice.certificate));

    if (ctx->certs == NULL ) {
        ASN_ALLOC(ctx->certs);
    }

    DO(ASN_SET_ADD(&ctx->certs->list, cert_choices));
    cert_choices = NULL;

cleanup:

    ASN_FREE(&CertificateChoices_desc, cert_choices);

    return ret;
}

int esigned_data_add_crl(SignedDataEngine *ctx, const CertificateList_t *crl)
{
    int ret = RET_OK;
    RevocationInfoChoice_t *revoc_info_choice = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(crl != NULL);

    ASN_ALLOC(revoc_info_choice);

    revoc_info_choice->present = RevocationInfoChoice_PR_crl;
    DO(asn_copy(&CertificateList_desc, crl, &revoc_info_choice->choice.crl));

    if (ctx->revoc_choices == NULL ) {
        ASN_ALLOC(ctx->revoc_choices);
    }

    DO(ASN_SET_ADD(&ctx->revoc_choices->list, revoc_info_choice));
    revoc_info_choice = NULL;

cleanup:

    ASN_FREE(&RevocationInfoChoice_desc, revoc_info_choice);

    return ret;
}

int esigned_data_add_signer(SignedDataEngine *ctx, SignerInfoEngine *signer)
{
    int ret = RET_OK;
    LOG_ENTRY();


    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(signer != NULL);

    REALLOC_CHECKED(ctx->sinfos.sinfo, ++ctx->sinfos.size * sizeof(SignerInfoEngine *), ctx->sinfos.sinfo);
    ctx->sinfos.sinfo[ctx->sinfos.size - 1] = signer;

cleanup:
    return ret;
}

int esigned_data_generate(const SignedDataEngine *ctx, SignedData_t **sdata)
{
    int ret = RET_OK;
    INTEGER_t *version = NULL;

    SignerInfo_t *sinfo = NULL;
    SignerInfos_t *sinfos = NULL;

    AlgorithmIdentifiers_t *digest_aids = NULL;
    DigestAlgorithmIdentifier_t *digest_aid = NULL;
    SignedData_t *signed_data = NULL;

    int i;
    long version_value;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(sdata != NULL);

    if (!ctx->info) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CONTEXT_NOT_READY);
    }

    version_value = pkix_check_oid_parent(&ctx->info->eContentType, oids_get_oid_numbers_by_id(OID_DATA_ID)) ? 1 : 3;
    DO(asn_create_integer_from_long(version_value, &version));

    ASN_ALLOC(digest_aids);
    ASN_ALLOC(sinfos);

    for (i = 0; i < ctx->sinfos.size; i++) {
        if (ctx->encap_data) {
            DO(esigner_info_set_data(ctx->sinfos.sinfo[i], &ctx->info->eContentType, ctx->encap_data));
        } else if (ctx->encap_hash_data) {
            DO(esigner_info_set_hash_data(ctx->sinfos.sinfo[i], &ctx->info->eContentType, ctx->encap_hash_data));
        } else if (ctx->info->eContent) {
            DO(esigner_info_set_data(ctx->sinfos.sinfo[i], &ctx->info->eContentType, ctx->info->eContent));
        } else {
            SET_ERROR(RET_PKIX_CONTEXT_NOT_READY);
        }

        DO(esigner_info_generate(ctx->sinfos.sinfo[i], &sinfo));
        CHECK_NOT_NULL(digest_aid = asn_copy_with_alloc(&DigestAlgorithmIdentifier_desc, &sinfo->digestAlgorithm));

        DO(ASN_SET_ADD(&digest_aids->list, digest_aid));
        digest_aid = NULL;
        DO(ASN_SET_ADD(&sinfos->list, sinfo));
        sinfo = NULL;
    }

    ASN_ALLOC(signed_data);

    DO(asn_copy(&CMSVersion_desc, version, &signed_data->version));
    DO(asn_copy(&DigestAlgorithmIdentifiers_desc, digest_aids, &signed_data->digestAlgorithms));
    DO(asn_copy(&EncapsulatedContentInfo_desc, ctx->info, &signed_data->encapContentInfo));
    DO(asn_copy(&SignerInfos_desc, sinfos, &signed_data->signerInfos));

    if (ctx->certs != NULL ) {
        CHECK_NOT_NULL(signed_data->certificates = asn_copy_with_alloc(&CertificateSet_desc, ctx->certs));
    }
    if (ctx->revoc_choices != NULL ) {
        CHECK_NOT_NULL(signed_data->crls = asn_copy_with_alloc(&RevocationInfoChoices_desc, ctx->revoc_choices));
    }

    *sdata = signed_data;

cleanup:

    ASN_FREE(&INTEGER_desc, version);
    ASN_FREE(&SignerInfo_desc, sinfo);
    ASN_FREE(&DigestAlgorithmIdentifier_desc, digest_aid);
    ASN_FREE(&SignerInfos_desc, sinfos);
    ASN_FREE(&AlgorithmIdentifiers_desc, digest_aids);

    if (RET_OK != ret) {
        ASN_FREE(&SignedData_desc, signed_data);
    }

    return ret;
}
