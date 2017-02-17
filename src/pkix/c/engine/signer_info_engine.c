/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "signer_info_engine.h"

#include "oids.h"
#include "pkix_macros_internal.h"
#include "pkix_utils.h"
#include "asn1_utils.h"
#include "log_internal.h"
#include "cert.h"
#include "signer_info.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/signer_info_engine.c"

#define SIGNER_INFO_VERSION 1

struct SignerInfoEngine_st {
    const SignAdapter      *sa;                     /** Адаптер подписи подписчика */
    const DigestAdapter
    *ess_da;                 /** Адаптер хэширования для вычисления SigningCertificateV2 */
    const DigestAdapter
    *data_da;                /** Адаптер хэширования данных с EncapsulatedContentInfo */
    Certificate_t          *signer_cert;            /** Сертификат подписчика */
    SignerIdentifier_t     *signer_id;              /** Информация про подписчика */
    bool
    add_bes_attrs;          /** Определяет, добавлять ли при генерации обязательные атрибуты формата CAdES-BES. По умолчанию - добавлять */
    Attributes_t           *signed_attrs;           /** Набор подписываемых атрибутов */
    Attributes_t           *unsigned_attrs;         /** Набор неподписываемых атрибутов */
    OBJECT_IDENTIFIER_t    *data_type_oid;          /** Тип подписываемых данных */
    OCTET_STRING_t
    *data;                   /** Байтовое представление подписываемых данных */
    OCTET_STRING_t
    *hash_data;              /** Байтовое представление хэша от подписываемых данных */
};

/**
 * Инициализирует ESSCertIDv2 с вычислением хеша сертификата.
 *
 * @param ess_cert_id    объект ESSCertIDv2
 * @param ctx контекст
 *
 * @return код ошибки
 */
static int create_ess_cert_id(ESSCertIDv2_t **ess_cert_id, const SignerInfoEngine *ctx)
{
    int ret = RET_OK;

    Hash_t *hash = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    IssuerSerial_t *issuer_serial = NULL;
    GeneralNames_t *general_names = NULL;
    GeneralName_t *general_name = NULL;
    ESSCertIDv2_t *cert_id = NULL;

    ByteArray *encoded = NULL;
    ByteArray *digest = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ess_cert_id != NULL);

    DO(ctx->ess_da->get_alg(ctx->ess_da, &aid));

    ASN_ALLOC(general_name);
    general_name->present = GeneralName_PR_directoryName;
    DO(asn_copy(&Name_desc, &ctx->signer_cert->tbsCertificate.issuer, &general_name->choice.directoryName));

    ASN_ALLOC(general_names);
    DO(ASN_SET_ADD(&general_names->list, (void *)general_name));
    general_name = NULL;

    ASN_ALLOC(issuer_serial);
    DO(asn_copy(&GeneralNames_desc, general_names, &issuer_serial->issuer));
    DO(asn_copy(&CertificateSerialNumber_desc, &ctx->signer_cert->tbsCertificate.serialNumber,
            &issuer_serial->serialNumber));

    DO(cert_encode(ctx->signer_cert, &encoded));

    DO(ctx->ess_da->update(ctx->ess_da, encoded));
    DO(ctx->ess_da->final(ctx->ess_da, &digest));

    DO(asn_create_octstring_from_ba(digest, &hash));

    ASN_ALLOC(cert_id);
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &cert_id->hashAlgorithm));
    DO(asn_copy(&Hash_desc, hash, &cert_id->certHash));

    DO(asn_copy(&IssuerSerial_desc, issuer_serial, &cert_id->issuerSerial));

    *ess_cert_id = cert_id;

cleanup:

    ASN_FREE(&Hash_desc, hash);
    ASN_FREE(&GeneralName_desc, general_name);
    ASN_FREE(&GeneralNames_desc, general_names);
    ASN_FREE(&IssuerSerial_desc, issuer_serial);
    ASN_FREE(&AlgorithmIdentifier_desc, aid);

    ba_free(digest);
    ba_free(encoded);

    if (RET_OK != ret) {
        ASN_FREE(&ESSCertIDv2_desc, cert_id);
    }

    return ret;
}

int esigner_info_alloc(const SignAdapter *sa,
        const DigestAdapter *data_da,
        const DigestAdapter *ess_da,
        SignerInfoEngine **ctx)
{
    int ret = RET_OK;
    SignerInfoEngine *engine = NULL;
    SignerIdentifierIm_t *signer_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(data_da != NULL);

    CALLOC_CHECKED(engine, sizeof(SignerInfoEngine));

    engine->sa = sa;
    engine->data_da = data_da;
    engine->ess_da = (ess_da != NULL ) ? ess_da : data_da;

    DO(engine->sa->get_cert(engine->sa, &engine->signer_cert));

    engine->add_bes_attrs = true;

    ASN_ALLOC(signer_id);

    signer_id->present = SignerIdentifierIm_PR_issuerAndSerialNumber;
    DO(asn_copy(&CertificateSerialNumber_desc,
            &engine->signer_cert->tbsCertificate.serialNumber,
            &signer_id->choice.issuerAndSerialNumber.serialNumber));
    DO(asn_copy(&Name_desc, &engine->signer_cert->tbsCertificate.issuer, &signer_id->choice.issuerAndSerialNumber.issuer));

    CHECK_NOT_NULL(engine->signer_id = ANY_new_fromType(&SignerIdentifierIm_desc, signer_id));

    *ctx = engine;

cleanup:

    if (RET_OK != ret) {
        esigner_info_free(engine);
    }
    ASN_FREE(&SignerIdentifierIm_desc, signer_id);

    return ret;
}

void esigner_info_free(SignerInfoEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        ASN_FREE(&Certificate_desc, ctx->signer_cert);
        ASN_FREE(&SignerIdentifier_desc, ctx->signer_id);
        ASN_FREE(&Attributes_desc, ctx->signed_attrs);
        ASN_FREE(&Attributes_desc, ctx->unsigned_attrs);
        ASN_FREE(&OBJECT_IDENTIFIER_desc, ctx->data_type_oid);
        ASN_FREE(&OCTET_STRING_desc, ctx->data);
        ASN_FREE(&OCTET_STRING_desc, ctx->hash_data);

        free(ctx);
    }
}

int esigner_info_set_bes_attrs(SignerInfoEngine *ctx, bool flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    ctx->add_bes_attrs = flag;

cleanup:
    return ret;
}

int esigner_info_set_signed_attrs(SignerInfoEngine *ctx, const SignedAttributes_t *signed_attrs)
{
    ByteArray *encoded = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    /* Прогоняем набор атрибутов через der кодирование и ber декодирование для их принудительной сортировки. */
    DO(asn_encode_ba(&SignedAttributesDer_desc, signed_attrs, &encoded));

    ASN_FREE(&Attributes_desc, ctx->signed_attrs);
    CHECK_NOT_NULL(ctx->signed_attrs = asn_decode_ba_with_alloc(&Attributes_desc, encoded));

cleanup:

    ba_free(encoded);

    return ret;
}

int esigner_info_set_unsigned_attrs(SignerInfoEngine *ctx, const Attributes_t *unsigned_attrs)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    if (ctx->unsigned_attrs) {
        ASN_FREE_CONTENT_PTR(&Attributes_desc, ctx->unsigned_attrs);
    } else {
        ASN_ALLOC(ctx->unsigned_attrs);
    }
    DO(asn_copy(&Attributes_desc, unsigned_attrs, ctx->unsigned_attrs));
cleanup:
    return ret;
}

int esigner_info_add_signed_attr(SignerInfoEngine *ctx, const Attribute_t *signed_attr)
{
    int ret = RET_OK;
    Attribute_t *attr = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    if (ctx->signed_attrs == NULL) {
        ASN_ALLOC(ctx->signed_attrs);
    }

    CHECK_NOT_NULL(attr = asn_copy_with_alloc(&Attribute_desc, signed_attr));
    DO(ASN_SET_ADD(&ctx->signed_attrs->list, attr));
    attr = NULL;

cleanup:

    ASN_FREE(&Attribute_desc, attr);

    return ret;
}

int esigner_info_add_unsigned_attr(SignerInfoEngine *ctx, const Attribute_t *unsigned_attr)
{
    int ret = RET_OK;
    Attribute_t *attr = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    if (ctx->unsigned_attrs == NULL) {
        ASN_ALLOC(ctx->unsigned_attrs);
    }

    CHECK_NOT_NULL(attr = asn_copy_with_alloc(&Attribute_desc, unsigned_attr));
    DO(asn_set_add(&ctx->unsigned_attrs->list, attr));
    attr = NULL;

cleanup:

    ASN_FREE(&Attribute_desc, attr);

    return ret;
}

int esigner_info_set_data(SignerInfoEngine *ctx,
        const OBJECT_IDENTIFIER_t *data_type_oid,
        const OCTET_STRING_t *data)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data_type_oid != NULL);
    CHECK_PARAM(data != NULL);

    CHECK_NOT_NULL(ctx->data_type_oid = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, data_type_oid));
    CHECK_NOT_NULL(ctx->data = asn_copy_with_alloc(&OCTET_STRING_desc, data));

cleanup:

    return ret;
}

int esigner_info_set_hash_data(SignerInfoEngine *ctx,
        const OBJECT_IDENTIFIER_t *data_type_oid,
        const OCTET_STRING_t *hash_data)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(data_type_oid != NULL);
    CHECK_PARAM(hash_data != NULL);

    CHECK_NOT_NULL(ctx->data_type_oid = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, data_type_oid));
    CHECK_NOT_NULL(ctx->hash_data = asn_copy_with_alloc(&OCTET_STRING_desc, hash_data));

cleanup:

    return ret;
}

/**
 * Получение подписываемых атрибутов, а так же возврат байтового представления
 * подписываемых атрибутов в DER-кодировании.
 * Выделяемая память требует освобождения.
 *
 * @param ctx контекст
 * @param signed_attrs указатель на создаваемые атрибуты
 * @param signed_attrs_bytes указатель на выделяемую память, содержащую DER-представление.
 *
 * @return код ошибки
 */
static int get_signed_attrs(const SignerInfoEngine *ctx,
        SignedAttributes_t **signed_attrs,
        ByteArray **signed_attrs_bytes)
{
    int ret = RET_OK;

    ESSCertIDv2_t *ess_cert = NULL;
    ESSCertIDv2s_t *ess_certs = NULL;
    SigningCertificateV2_t *signing_cert = NULL;
    OCTET_STRING_t *digest = NULL;

    Attribute_t *data = NULL;
    Attribute_t *hash = NULL;
    Attribute_t *sign = NULL;
    Attribute_t *attr = NULL;

    ByteArray *data_ba = NULL;
    ByteArray *hash_ba = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(signed_attrs != NULL);

    if (ctx->add_bes_attrs) {

        if (ctx->hash_data) {
            DO(asn_OCTSTRING2ba(ctx->hash_data, &hash_ba));
        } else if (ctx->data) {
            DO(asn_OCTSTRING2ba(ctx->data, &data_ba));
            DO(ctx->data_da->update(ctx->data_da, data_ba));
            DO(ctx->data_da->final(ctx->data_da, &hash_ba));
        }  else {
            LOG_ERROR();
            SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
        }

        ASN_ALLOC(ess_certs);
        DO(create_ess_cert_id(&ess_cert, ctx));
        DO(ASN_SET_ADD(&ess_certs->list, ess_cert));
        ess_cert = NULL;

        ASN_ALLOC(signing_cert);
        DO(asn_copy(&ESSCertIDv2s_desc, ess_certs, &signing_cert->certs));

        ASN_ALLOC(data);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_CONTENT_TYPE_ID), &data->type));
        DO(ASN_SET_ADD(&data->value.list, ANY_new_fromType(&OBJECT_IDENTIFIER_desc, ctx->data_type_oid)));

        DO(asn_create_octstring_from_ba(hash_ba, &digest));

        ASN_ALLOC(hash);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID), &hash->type));
        DO(ASN_SET_ADD(&hash->value.list, ANY_new_fromType(&OCTET_STRING_desc, digest)));

        ASN_ALLOC(sign);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_AA_SIGNING_CERTIFICATE_V2_ID), &sign->type));
        DO(ASN_SET_ADD(&sign->value.list, ANY_new_fromType(&SigningCertificateV2_desc, signing_cert)));

        ASN_ALLOC(*signed_attrs);
        DO(ASN_SET_ADD(&(*signed_attrs)->list, data));
        data = NULL;
        DO(ASN_SET_ADD(&(*signed_attrs)->list, hash));
        hash = NULL;
        DO(ASN_SET_ADD(&(*signed_attrs)->list, sign));
        sign = NULL;

        if (ctx->signed_attrs != NULL ) {
            int i;

            for (i = 0; i < ctx->signed_attrs->list.count; i++) {
                CHECK_NOT_NULL(attr = asn_copy_with_alloc(&Attribute_desc, ctx->signed_attrs->list.array[i]));

                DO(ASN_SET_ADD(&(*signed_attrs)->list, attr));
                attr = NULL;
            }
        }

    } else {

        ASN_ALLOC(*signed_attrs);
        DO(asn_copy(&Attributes_desc, ctx->signed_attrs, *signed_attrs));
    }

    /* Принудительное DER кодирование для пересортировывания атрибутов. */
    DO(asn_encode_ba(&SignedAttributesDer_desc, *signed_attrs, signed_attrs_bytes));
    ASN_FREE_CONTENT_PTR(&SignedAttributes_desc, *signed_attrs);
    DO(asn_decode_ba(&SignedAttributes_desc, *signed_attrs, *signed_attrs_bytes));

cleanup:

    ASN_FREE(&ESSCertIDv2_desc, ess_cert);
    ASN_FREE(&ESSCertIDv2s_desc, ess_certs);
    ASN_FREE(&SigningCertificateV2_desc, signing_cert);
    ASN_FREE(&OCTET_STRING_desc, digest);
    ASN_FREE(&Attribute_desc, data);
    ASN_FREE(&Attribute_desc, hash);
    ASN_FREE(&Attribute_desc, sign);
    ASN_FREE(&Attribute_desc, attr);

    ba_free(hash_ba);
    ba_free(data_ba);

    if (RET_OK != ret) {
        ASN_FREE(&Attributes_desc, *signed_attrs);
        *signed_attrs = NULL;
        if (signed_attrs_bytes) {
            free(*signed_attrs_bytes);
        }
    }

    return ret;
}

int esigner_info_generate(const SignerInfoEngine *ctx, SignerInfo_t **sinfo)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t *s_aid = NULL;
    AlgorithmIdentifier_t *d_aid = NULL;
    OCTET_STRING_t *sign = NULL;
    Attributes_t *s_attrs = NULL;
    SignerInfo_t *signer_info = NULL;

    ByteArray *encoded = NULL;
    ByteArray *sign_ba = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(sinfo != NULL);

    DO(get_signed_attrs(ctx, &s_attrs, &encoded));

    DO(ctx->sa->sign_data(ctx->sa, encoded, &sign_ba));
    DO(ctx->sa->get_sign_alg(ctx->sa, &s_aid));
    DO(ctx->data_da->get_alg(ctx->data_da, &d_aid));

    DO(sign_ba_to_os(sign_ba, s_aid, &sign));

    CHECK_NOT_NULL(signer_info = sinfo_alloc());

    DO(sinfo_init(signer_info, SIGNER_INFO_VERSION, ctx->signer_id, d_aid, s_attrs, s_aid, sign, ctx->unsigned_attrs));

    *sinfo = signer_info;

cleanup:

    ASN_FREE(&AlgorithmIdentifier_desc, s_aid);
    ASN_FREE(&AlgorithmIdentifier_desc, d_aid);
    ASN_FREE(&OCTET_STRING_desc, sign);
    ASN_FREE(&Attributes_desc, s_attrs);

    ba_free(encoded);
    ba_free(sign_ba);

    if (RET_OK != ret) {
        ASN_FREE(&SignerInfo_desc, signer_info);
    }

    return ret;
}

