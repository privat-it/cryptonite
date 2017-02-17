/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "enveloped_data_engine.h"

#include "enveloped_data.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "pkix_utils.h"
#include "asn1_utils.h"
#include "cryptonite_manager.h"
#include "aid.h"
#include "spki.h"
#include "cert.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/enveloped_data_engine.c"
/** Максимальный размер идентификатора. */
#define MAX_OID_LEN 20

struct EnvelopedDataEngine_st {
    /* Набор атрибутов, которые не шифруются вместе с сообщением */
    UnprotectedAttributes_t *attrs;
    /* Сохранять ли сертификат отправителя в структуре */
    bool is_save_cert;
    /* Сохранять ли зашифрованные данные в контейнере */
    bool is_save_data;
    /* Идентификатор данных */
    OBJECT_IDENTIFIER_t *data_oid;
    /* Идентификатор алгоритма шифрования */
    OBJECT_IDENTIFIER_t *cipher_oid;
    /* Данные для формирования контейнера */
    ByteArray *data;
    /* Сертификат отправителя */
    Certificate_t *originator_cert;
    /* Набор сертификатов получателей */
    CertificateSet_t *recipient_certs;
    PrngCtx *prng;
    /* Адаптер выработки общего секрета */
    const DhAdapter *dha;
};

/**
 * Создает IssuerSerial по сертификату.
 *
 * @param cert сертификат
 * @param issuer_sn объект IssuerSerial
 *
 * @return код ошибки
 */
static int cert_get_issuer_and_sn(const Certificate_t *cert, IssuerAndSerialNumber_t **issuer_sn)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t *serial = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(issuer_sn != NULL);

    ASN_ALLOC(serial);

    DO(asn_copy(&Name_desc, &cert->tbsCertificate.issuer, &serial->issuer));
    DO(asn_copy(&CertificateSerialNumber_desc, &cert->tbsCertificate.serialNumber, &serial->serialNumber));

    *issuer_sn = serial;

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&IssuerAndSerialNumber_desc, serial);
    }

    return ret;
}

/**
 * Создает RecipientEncryptedKey на основе готовых данных.
 *
 * @param ctx        контекст
 * @param index      индекс
 * @param session_key сессионный ключ
 * @param recipient_encrypted_key объект RecipientEncryptedKey
 *
 * @return код ошибки
 */
static int generate_recipient_encrypted_key(const DhAdapter *dha, const Certificate_t *recipient_cert,
        const ByteArray *session_key, const ByteArray *rnd_bytes, RecipientEncryptedKey_t **recipient_encrypted_key)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t *issuer_and_sn = NULL;
    KeyAgreeRecipientIdentifier_t *rid = NULL;
    OCTET_STRING_t *encrypted_key = NULL;
    RecipientEncryptedKey_t *key = NULL;
    ByteArray *recipient_pub_key = NULL;
    ByteArray *wraped = NULL;

    LOG_ENTRY();

    CHECK_PARAM(recipient_encrypted_key != NULL);

    DO(cert_get_issuer_and_sn(recipient_cert, &issuer_and_sn));

    ASN_ALLOC(rid);
    rid->present = KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber;
    DO(asn_copy(&IssuerAndSerialNumber_desc, issuer_and_sn, &rid->choice.issuerAndSerialNumber));

    DO(spki_get_pub_key(&recipient_cert->tbsCertificate.subjectPublicKeyInfo, &recipient_pub_key));

    DO(wrap_session_key(dha, recipient_pub_key, session_key, rnd_bytes, &wraped));
    DO(asn_create_octstring_from_ba(wraped, &encrypted_key));

    ASN_ALLOC(key);

    DO(asn_copy(&OCTET_STRING_desc, encrypted_key, &key->encryptedKey));
    DO(asn_copy(&KeyAgreeRecipientIdentifier_desc, rid, &key->rid));

    *recipient_encrypted_key = key;

cleanup:

    ASN_FREE(&IssuerAndSerialNumber_desc, issuer_and_sn);
    ASN_FREE(&KeyAgreeRecipientIdentifier_desc, rid);
    ASN_FREE(&OCTET_STRING_desc, encrypted_key);

    ba_free(recipient_pub_key);
    ba_free(wraped);

    if (RET_OK != ret) {
        ASN_FREE(&RecipientEncryptedKey_desc, key);
    }

    return ret;
}

/**
 * Создает RecipientInfo на основе готовых данных.
 *
 * @param ctx            контекст
 * @param originator     объект OriginatorIdentifierOrKey
 * @param session_key сессионный ключ
 * @param recipient_info объект RecipientInfo
 *
 * @return код ошибки
 */
static int generate_recipient(const EnvelopedDataEngine *ctx, const DhAdapter *dha, const Certificate_t *recipient_cert,
        const OriginatorIdentifierOrKey_t *originator, const ByteArray *session_key, RecipientInfo_t **recipient_info)
{
    int ret = RET_OK;

    CMSVersion_t *version = NULL;
    AlgorithmIdentifier_t *params_aid = NULL;
    KeyEncryptionAlgorithmIdentifier_t *key_encryption_algorithm = NULL;
    RecipientEncryptedKeys_t *keys = NULL;
    KeyAgreeRecipientInfo_t *key_agree_recipient_info = NULL;
    RecipientEncryptedKey_t *encrypted_key = NULL;
    RecipientInfo_t *info = NULL;
    ByteArray *rnd_bytes = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx->recipient_certs != NULL);
    CHECK_PARAM(ctx->recipient_certs->list.count != 0);

    DO(asn_create_integer_from_long(3, &version));
    DO(aid_create_gost28147_wrap(&params_aid));

    CHECK_NOT_NULL(key_encryption_algorithm = aid_alloc());
    DO(aid_init_by_oid(key_encryption_algorithm,
            oids_get_oid_numbers_by_id(OID_DH_SINGLE_PASS_COFACTOR_DH_GOST34311KDF_SCHEME_ID)));

    DO(asn_create_any(&AlgorithmIdentifier_desc, params_aid, &key_encryption_algorithm->parameters));

    rnd_bytes = ba_alloc_by_len(64);
    DO(prng_next_bytes(ctx->prng, rnd_bytes));

    ASN_ALLOC(keys);

    DO(generate_recipient_encrypted_key(dha, recipient_cert, session_key, rnd_bytes, &encrypted_key));
    DO(ASN_SET_ADD(&keys->list, encrypted_key));
    encrypted_key = NULL;

    ASN_ALLOC(key_agree_recipient_info);

    DO(asn_copy(&KeyEncryptionAlgorithmIdentifier_desc, key_encryption_algorithm,
            &key_agree_recipient_info->keyEncryptionAlgorithm));
    DO(asn_copy(&RecipientEncryptedKeys_desc, keys, &key_agree_recipient_info->recipientEncryptedKeys));
    DO(asn_copy(&CMSVersion_desc, version, &key_agree_recipient_info->version));
    DO(asn_copy(&OriginatorIdentifierOrKey_desc, originator, &key_agree_recipient_info->originator));

    DO(asn_create_octstring_from_ba(rnd_bytes, &key_agree_recipient_info->ukm));

    ASN_ALLOC(info);
    info->present = RecipientInfo_PR_kari;
    DO(asn_copy(&KeyAgreeRecipientInfo_desc, key_agree_recipient_info, &info->choice.kari));

    *recipient_info = info;

cleanup:

    ba_free(rnd_bytes);
    ASN_FREE(&CMSVersion_desc, version);
    ASN_FREE(&AlgorithmIdentifier_desc, params_aid);
    ASN_FREE(&KeyEncryptionAlgorithmIdentifier_desc, key_encryption_algorithm);
    ASN_FREE(&RecipientEncryptedKeys_desc, keys);
    ASN_FREE(&KeyAgreeRecipientInfo_desc, key_agree_recipient_info);
    ASN_FREE(&RecipientEncryptedKey_desc, encrypted_key);

    if (RET_OK != ret) {
        ASN_FREE(&RecipientInfo_desc, info);
    }

    return ret;
}

/**
 * Создает OriginatorIdentifierOrKey на основе готовых данных.
 *
 * @param ctx        контекст
 * @param originator объект OriginatorIdentifierOrKey
 *
 * @return код ошибки
 */
static int generate_originator_id_by_issuer_and_sn(const EnvelopedDataEngine *ctx,
        OriginatorIdentifierOrKey_t **originator)
{
    int ret = RET_OK;
    IssuerAndSerialNumber_t *issuer_serial = NULL;
    OriginatorIdentifierOrKey_t *identifier = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(originator != NULL);

    ASN_ALLOC(identifier);

    DO(cert_get_issuer_and_sn(ctx->originator_cert, &issuer_serial));
    identifier->present = OriginatorIdentifierOrKey_PR_issuerAndSerialNumber;
    DO(asn_copy(&IssuerAndSerialNumber_desc, issuer_serial, &identifier->choice.issuerAndSerialNumber));

    *originator = identifier;

cleanup:

    ASN_FREE(&IssuerAndSerialNumber_desc, issuer_serial);

    if (RET_OK != ret) {
        ASN_FREE(&OriginatorIdentifierOrKey_desc, identifier);
    }

    return ret;
}

/**
 * Создает OriginatorIdentifierOrKey на основе готовых данных.
 *
 * @param aid        идентификатор алгоритма
 * @param key        открытый ключ
 * @param originator объект OriginatorIdentifierOrKey
 *
 * @return код ошибки
 */
static int generate_originator_id_by_key(const AlgorithmIdentifier_t *aid, const ByteArray *key,
        OriginatorIdentifierOrKey_t **originator)
{
    int ret = RET_OK;
    OriginatorPublicKey_t *originator_key = NULL;
    OriginatorIdentifierOrKey_t *identifier = NULL;
    BIT_STRING_t *pub_key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(originator != NULL);

    DO(convert_pubkey_bytes_to_bitstring(&aid->algorithm, key, &pub_key));

    ASN_ALLOC(originator_key);

    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &originator_key->algorithm));
    DO(asn_copy(&BIT_STRING_desc, pub_key, &originator_key->publicKey));

    ASN_ALLOC(identifier);
    identifier->present = OriginatorIdentifierOrKey_PR_originatorKey;
    DO(asn_copy(&OriginatorPublicKey_desc, originator_key, &identifier->choice.originatorKey));

    *originator = identifier;

cleanup:

    ASN_FREE(&OriginatorPublicKey_desc, originator_key);
    ASN_FREE(&BIT_STRING_desc, pub_key);

    if (ret != RET_OK) {
        ASN_FREE(&OriginatorIdentifierOrKey_desc, identifier);
    }

    return ret;
}

int eenvel_data_alloc(const DhAdapter *dha, EnvelopedDataEngine **ctx)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(dha != NULL);

    CALLOC_CHECKED(*ctx, sizeof(EnvelopedDataEngine));

    (*ctx)->dha = dha;
    (*ctx)->is_save_data = true;

cleanup:

    return ret;
}

void eenvel_data_free(EnvelopedDataEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        ASN_FREE(&Certificate_desc, ctx->originator_cert);
        ASN_FREE(&CertificateSet_desc, ctx->recipient_certs);
        ASN_FREE(&OBJECT_IDENTIFIER_desc, ctx->data_oid);
        ASN_FREE(&OBJECT_IDENTIFIER_desc, ctx->cipher_oid);
        ASN_FREE(&UnprotectedAttributes_desc, ctx->attrs);
        ba_free(ctx->data);
        prng_free(ctx->prng);
        free(ctx);
    }
}

int eenvel_data_set_originator_cert(EnvelopedDataEngine *ctx, const Certificate_t *cert)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert != NULL);

    CHECK_NOT_NULL(ctx->originator_cert = asn_copy_with_alloc(&Certificate_desc, cert));

cleanup:

    return ret;
}

int eenvel_data_set_unprotected_attrs(EnvelopedDataEngine *ctx, const UnprotectedAttributes_t *attrs)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(attrs != NULL);

    DO(asn_copy(&UnprotectedAttributes_desc, attrs, &ctx->attrs));

cleanup:

    return ret;
}

int eenvel_data_set_data(EnvelopedDataEngine *ctx, const OBJECT_IDENTIFIER_t *oid, const ByteArray *data)
{
    int ret = RET_OK
            LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(data != NULL);

    CHECK_NOT_NULL(ctx->data_oid = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, oid));
    CHECK_NOT_NULL(ctx->data = ba_copy_with_alloc(data, 0, 0));

cleanup:

    return ret;
}

int eenvel_data_set_encription_oid(EnvelopedDataEngine *ctx, const OBJECT_IDENTIFIER_t *oid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(oid != NULL);

    CHECK_NOT_NULL(ctx->cipher_oid = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, oid));

cleanup:

    return ret;
}

int eenvel_data_set_save_cert_optional(EnvelopedDataEngine *ctx, bool is_save_cert)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    ctx->is_save_cert = is_save_cert;

cleanup:

    return ret;
}

int eenvel_data_set_save_data_optional(EnvelopedDataEngine *ctx, bool is_save_data)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);

    ctx->is_save_data = is_save_data;

cleanup:

    return ret;
}

int eenvel_data_set_prng(EnvelopedDataEngine *ctx, PrngCtx *prng)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;

    CHECK_PARAM(ctx);
    CHECK_PARAM(prng);

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    prng_next_bytes(prng, seed);

    CHECK_NOT_NULL(ctx->prng = prng_alloc(PRNG_MODE_DSTU, seed));

cleanup:

    ba_free(seed);

    return ret;
}

int eenvel_data_add_recipient(EnvelopedDataEngine *ctx, const Certificate_t *cert)
{
    int ret = RET_OK;
    CertificateChoices_t *cert_choice = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(cert != NULL);

    ASN_ALLOC(cert_choice);

    cert_choice->present = CertificateChoices_PR_certificate;
    DO(asn_copy(&Certificate_desc, cert, &cert_choice->choice.certificate));

    if (ctx->recipient_certs == NULL ) {
        ASN_ALLOC(ctx->recipient_certs);
    }

    DO(ASN_SET_ADD(&ctx->recipient_certs->list, cert_choice));
    cert_choice = NULL;

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&CertificateChoices_desc, cert_choice);
    }

    return ret;
}

int eenvel_data_generate(EnvelopedDataEngine *ctx, EnvelopedData_t **env_data, ByteArray **enc_data)
{
    int ret = RET_OK;

    EncryptedContentInfo_t *encr_content_info = NULL;
    RecipientInfo_t *recipient = NULL;
    RecipientInfos_t *recipients = NULL;
    OriginatorIdentifierOrKey_t *originator = NULL;
    AlgorithmIdentifier_t *sign_aid = NULL;
    OCTET_STRING_t *encr_content = NULL;
    CertificateSet_t *certs = NULL;
    CertificateChoices_t *cert = NULL;
    EnvelopedData_t *enveloped_data = NULL;
    NULL_t *asn_null = NULL;
    Dstu4145Ctx *originator_dstu_ctx = NULL;
    Dstu4145Ctx *recipient_dstu_ctx = NULL;
    ByteArray *gen_privkey = NULL;
    ByteArray *pubkey = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    DhAdapter *dha = NULL;
    ByteArray *rnd_bytes = NULL;
    ByteArray *pub_key = NULL;
    bool flag;
    bool is_equals;
    int i;
    const Certificate_t *recipient_cert;
    ByteArray *encrypted_data = NULL;
    ByteArray *session_secret_key = NULL;
    AlgorithmIdentifier_t *cipher_aid = NULL;
    CipherAdapter *ca = NULL;
    OriginatorInfo_t *originator_info = NULL;
    INTEGER_t *version = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(env_data != NULL);

    if (!ctx->recipient_certs || ctx->recipient_certs->list.count == 0) {
        SET_ERROR(RET_PKIX_ENVDATA_NO_RECIPIENT);
    }

    if (ctx->cipher_oid == NULL) {
        SET_ERROR(RET_PKIX_ENVDATA_NO_ENC_OID);
    }

    if (ctx->prng == NULL) {
        SET_ERROR(RET_PKIX_ENVDATA_NO_PRNG);
    }

    if (ctx->data == NULL || ctx->data_oid == NULL) {
        SET_ERROR(RET_PKIX_ENVDATA_NO_CONTENT);
    }

    DO(gost28147_generate_key(ctx->prng, &session_secret_key));

    CHECK_NOT_NULL(rnd_bytes = ba_alloc_by_len(64));
    DO(prng_next_bytes(ctx->prng, rnd_bytes));

    DO(ctx->dha->get_pub_key(ctx->dha, &pub_key));
    DO(cert_check_pubkey_and_usage(ctx->originator_cert, pub_key, 0, &flag));
    if (!flag) {
        SET_ERROR(RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT);
    }

    DO(aid_get_dstu4145_params(&ctx->originator_cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &originator_dstu_ctx));

    ASN_ALLOC(asn_null);
    ASN_ALLOC(recipients);

    for (i = 0; i < ctx->recipient_certs->list.count; i++) {
        if (ctx->recipient_certs->list.array[i]->present != CertificateChoices_PR_certificate) {
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_OBJ);
        }

        recipient_cert = &ctx->recipient_certs->list.array[i]->choice.certificate;

        DO(aid_get_dstu4145_params(&recipient_cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &recipient_dstu_ctx));
        DO(dstu4145_equals_params(originator_dstu_ctx, recipient_dstu_ctx, &is_equals));

        if (!is_equals) {
            CHECK_NOT_NULL(sign_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &recipient_cert->signatureAlgorithm));
            ASN_FREE(&ANY_desc, sign_aid->parameters);
            sign_aid->parameters = NULL;

            if (pkix_check_oid_parent(&sign_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
                DO(asn_create_any(&NULL_desc, asn_null, &sign_aid->parameters));
            } else {
                SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
            }

            DO(dstu4145_generate_privkey(recipient_dstu_ctx, ctx->prng, &gen_privkey));
            DO(dstu4145_get_pubkey(recipient_dstu_ctx, gen_privkey, &qx, &qy));
            DO(dstu4145_compress_pubkey(recipient_dstu_ctx, qx, qy, &pubkey));

            DO(generate_originator_id_by_key(sign_aid, pubkey, &originator));

            DO(dh_adapter_init(gen_privkey, &recipient_cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &dha));
            DO(generate_recipient(ctx, dha, recipient_cert, originator, session_secret_key, &recipient));

            dh_adapter_free(dha);
            dha = NULL;
            ba_free(gen_privkey);
            gen_privkey = NULL;
            ba_free(pubkey);
            pubkey = NULL;
            ba_free(qx);
            qx = NULL;
            ba_free(qy);
            qy = NULL;
            aid_free(sign_aid);
            sign_aid = NULL;

        } else {
            DO(generate_originator_id_by_issuer_and_sn(ctx, &originator));
            DO(generate_recipient(ctx, ctx->dha, recipient_cert, originator, session_secret_key, &recipient));
        }

        DO(ASN_SET_ADD(&recipients->list, recipient));
        recipient = NULL;

        ASN_FREE(&OriginatorIdentifierOrKey_desc, originator);
        originator = NULL;

        dstu4145_free(recipient_dstu_ctx);
        recipient_dstu_ctx = NULL;
    }

    DO(get_gost28147_aid(ctx->prng, ctx->cipher_oid, ctx->originator_cert, &cipher_aid));
    DO(cipher_adapter_init(cipher_aid, &ca));

    ASN_ALLOC(encr_content_info);

    DO(asn_copy(&AlgorithmIdentifier_desc, cipher_aid, &encr_content_info->contentEncryptionAlgorithm));
    DO(asn_copy(&OBJECT_IDENTIFIER_desc, ctx->data_oid, &encr_content_info->contentType));

    DO(ca->encrypt(ca, session_secret_key, ctx->data, &encrypted_data));

    if (ctx->is_save_data) {
        DO(asn_create_octstring_from_ba(encrypted_data, &encr_content));
        CHECK_NOT_NULL(encr_content_info->encryptedContent = asn_copy_with_alloc(&OCTET_STRING_desc, encr_content));
    }

    if (ctx->is_save_cert) {
        ASN_ALLOC(cert);

        cert->present = CertificateChoices_PR_certificate;
        DO(asn_copy(&Certificate_desc, ctx->originator_cert, &cert->choice.certificate));

        ASN_ALLOC(certs);

        DO(ASN_SET_ADD(&certs->list, cert));
        cert = NULL;

        ASN_ALLOC(originator_info);
        CHECK_NOT_NULL(originator_info->certs = asn_copy_with_alloc(&CertificateSet_desc, certs));
    }

    CHECK_NOT_NULL(enveloped_data = env_data_alloc());

    DO(asn_create_integer_from_long(2, &version));
    DO(env_data_init(enveloped_data, version, originator_info, recipients, encr_content_info, ctx->attrs));

    *env_data = enveloped_data;
    enveloped_data = NULL;

    if (enc_data) {
        *enc_data = encrypted_data;
        encrypted_data = NULL;
    }

cleanup:

    ASN_FREE(&OriginatorInfo_desc, originator_info);
    ASN_FREE(&EncryptedContentInfo_desc, encr_content_info);
    ASN_FREE(&RecipientInfo_desc, recipient);
    ASN_FREE(&RecipientInfos_desc, recipients);
    ASN_FREE(&OriginatorIdentifierOrKey_desc, originator);
    ASN_FREE(&OCTET_STRING_desc, encr_content);
    ASN_FREE(&CertificateSet_desc, certs);
    ASN_FREE(&CertificateChoices_desc, cert);
    ASN_FREE(&INTEGER_desc, version);
    ASN_FREE(&NULL_desc, asn_null);

    aid_free(cipher_aid);
    aid_free(sign_aid);
    env_data_free(enveloped_data);

    dstu4145_free(originator_dstu_ctx);
    dstu4145_free(recipient_dstu_ctx);

    ba_free(pub_key);
    ba_free(rnd_bytes);
    ba_free(gen_privkey);
    ba_free(pubkey);
    ba_free(qx);
    ba_free(qy);
    ba_free(encrypted_data);
    ba_free_private(session_secret_key);

    dh_adapter_free(dha);
    cipher_adapter_free(ca);

    return ret;
}

