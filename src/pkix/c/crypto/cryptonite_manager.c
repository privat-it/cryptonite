/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "sha1.h"
#include "sha2.h"
#include "cryptonite_manager.h"
#include "pkix_utils.h"
#include "pkix_macros_internal.h"
#include "cryptonite_errors.h"
#include "oids.h"
#include "log_internal.h"
#include "gost34_311.h"
#include "aes.h"
#include "dstu4145.h"
#include "rs.h"
#include "prng.h"
#include "asn1_utils.h"
#include "cert.h"
#include "aid.h"
#include "spki.h"
#include "paddings.h"

#define SBOX_SIZE           128
#define DSTU4145_KEY_SIZE   64
#define GOST28147_KEY_SIZE  32
#define GOST3411_HASH_SIZE  32

#undef FILE_MARKER
#define FILE_MARKER "pki/crypto/cryptonite_manager.c"

static const uint8_t CFB_WRAP_OID[13] = {0x06, 0x0b, 0x2a, 0x86,
                                         0x24, 0x02, 0x01, 0x01,
                                         0x01, 0x01, 0x01, 0x01, 0x05
                                        };

typedef enum DigestModeId_st {
    DIGEST_MODE_GOST34311,
    DIGEST_MODE_SHA1,
    DIGEST_MODE_SHA2
} DigestModeId;

/**
 * Структура для хранения глобальных параметров механизма выработки хеш вектора.
 */
typedef struct CryptoniteDigestParams_st {
    DigestModeId mode_id;
    union {
        Gost34311Ctx *gost;
        Sha1Ctx *sha1;
        Sha2Ctx *sha2;
    } mode;
    AlgorithmIdentifier_t *digest_aid;  /**< ASN1 структура алгоритм хеширования */
} CryptoniteDigestParams;

/**
 * Структура для хранения глобальных параметров для шифрования.
 */
typedef struct CryptoniteCipherParams_st {
    /* ASN1 структура режима шифрования */
    AlgorithmIdentifier_t *asn_cipher_aid;
    /* Таблица замен ГОСТ 28147 */
    ByteArray *sbox;
    /* Вектор инициализации */
    ByteArray *cipher_init_vector;
} CryptoniteCipherParams;

/**
 * Структура для хранения глобальных параметров для общего секрета.
 */
typedef struct CryptoniteDhParams_st {
    /* ASN1 структура режима выробатки общего секрета */
    AlgorithmIdentifier_t *dh_aid;
    /* Закрытый ключ */
    ByteArray *key;
} CryptoniteDhParams;

/**
 * Перечисление для хранения текущего алгоритма подписи.
 */
typedef enum SignAlgId_st {
    DSTU4145,
    ECDSA,
    WRONG_ID
} SignAlgId;

/**
 * Структура для хранения глобальных параметров механизма подписи и ее проверки.
 */
typedef struct CryptoniteSignParams_st {
    /* Открытый ключ подписчика */
    BIT_STRING_t *public_key;
    /* ASN1 структура параметров ДСТУ 4145 */
    DSTU4145Params_t *asn_dstu_params;
    /* ASN1 структура параметров ДСТУ 4145 */
    ECParameters_t        *asn_ec_params;
    union {
        /* Cryptonite структура контекста ДСТУ 4145 */
        Dstu4145Ctx *dstu;
        /* Cryptonite структура контекста ECDSA */
        EcdsaCtx    *ecdsa;
    } alg_type;

    /* Закрытый ключ подписчика */
    ByteArray *private_key;
    /* Cryptonite структура контекста ГПСЧ */
    PrngCtx *prng_ctx;
    /* ASN1 структура информации о праметрах открытого/закрытого ключа */
    AlgorithmIdentifier_t *params_aid;
    /* ASN1 структура алгоритма подписи */
    AlgorithmIdentifier_t *signature_aid;
    /* ASN1 структура алгоритма хеширования */
    AlgorithmIdentifier_t *digest_aid;
    /* ASN1 структура параметров сертификата */
    Certificate_t *certificate;
    /* Признак присутствия сертификата в структуре */
    bool has_cert;
    /* Таблица замен ГОСТ 28147 для хеширования подписываемых данных */
    ByteArray *digest_sbox;
    /* Текущий алгоритм подписи */
    SignAlgId alg_marker;
} CryptoniteSignParams;

/**
 * Возвращает алгоритм хеширования в виде ASN1 структуры.
 *
 * @param adapter адаптер хэширования
 * @param digest_aid буфер для размещения ASN1 структуры хеш алгоритма
 *
 * @return код ошибки
 */
static int da_get_alg(const DigestAdapter *adapter, DigestAlgorithmIdentifier_t **digest_aid)
{
    int ret = RET_OK;
    CryptoniteDigestParams *d_params = NULL;

    LOG_ENTRY();

    CHECK_PARAM(adapter != NULL);
    CHECK_PARAM(digest_aid != NULL);

    d_params = (CryptoniteDigestParams *)adapter->ctx;

    CHECK_NOT_NULL(*digest_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, d_params->digest_aid));

cleanup:

    return ret;
}

/**
 * Возвращает таблицу замен.
 *
 * @param id   идентификатор предустановленной таблицы замен
 * @param sbox 128-байтный буфер для таблицы замен
 *
 * @return код ошибки
 */
static int get_sbox_by_id(Gost28147SboxId id, ByteArray **sbox)
{
    int ret = RET_OK;
    Gost28147Ctx *params = NULL;

    CHECK_PARAM(sbox != NULL);

    CHECK_NOT_NULL(params = gost28147_alloc(id));
    DO(gost28147_get_ext_sbox(params, sbox));

cleanup:

    gost28147_free(params);

    return ret;
}

/**
 * Инициализирует таблицу замен.
 *
 * @param aid  ASN1 структура алгоритма шифрования
 * @param sbox_buff буфер для таблицы замен
 *
 * @return код ошибки
 */
static int get_sbox_from_aid(const AlgorithmIdentifier_t *aid, ByteArray **sbox_buff)
{
    int ret = RET_OK;

    int i, j;
    int count;
    size_t dke_size;
    unsigned char *dke = NULL;
    uint8_t sbox[SBOX_SIZE] = {0};
    DSTU4145Params_t *dstu_params = NULL;

    LOG_ENTRY();

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sbox_buff != NULL);

    if (pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {

        CHECK_NOT_NULL(dstu_params = asn_any2type(aid->parameters, &DSTU4145Params_desc));
        if (dstu_params->dke) {
            DO(asn_OCTSTRING2bytes(dstu_params->dke, &dke, &dke_size));

            count = 0;
            for (i = 0; i < 8; i++) {
                for (j = 0; j < 16; j++) {
                    sbox[count++] = (dke[(i << 3) + (j >> 1)] >> ((~j & 1) << 2)) & 0xf;
                }
            }

            CHECK_NOT_NULL(*sbox_buff = ba_alloc_from_uint8(sbox, SBOX_SIZE));
        } else {
            DO(get_sbox_by_id(GOST28147_SBOX_ID_1, sbox_buff));
        }
    } else {
        DO(get_sbox_by_id(GOST28147_SBOX_ID_1, sbox_buff));
    }

cleanup:

    free(dke);
    ASN_FREE(&DSTU4145Params_desc, dstu_params);

    return ret;
}

int get_gost28147_params_by_os(const OCTET_STRING_t *sbox_os, Gost28147Ctx **params)
{
    int ret = RET_OK;

    int i, j;
    int count;
    size_t dke_size;
    unsigned char *dke = NULL;
    unsigned char sbox[SBOX_SIZE] = {0};
    Gost28147Ctx *gost_params = NULL;
    ByteArray *bsbox = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sbox_os != NULL);
    CHECK_PARAM(params != NULL);

    DO(asn_OCTSTRING2bytes(sbox_os, &dke, &dke_size));

    CHECK_PARAM(dke_size == (SBOX_SIZE >> 1));

    count = 0;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            sbox[count++] = (dke[(i << 3) + (j >> 1)] >> ((~j & 1) << 2)) & 0x0f;
        }
    }

    CHECK_NOT_NULL(bsbox = ba_alloc_from_uint8(sbox, SBOX_SIZE));
    CHECK_NOT_NULL(gost_params = gost28147_alloc_user_sbox(bsbox));

    *params = gost_params;
    gost_params = NULL;

cleanup:

    free(dke);
    gost28147_free(gost_params);
    ba_free(bsbox);

    return ret;
}

/** Вычисляет хеш-вектор от открытых данных.
 *
 * @param da адаптер хэширования
 * @param src открытые данные
 *
 * @return код ошибки
 */
static int da_update(const struct DigestAdapter_st *da, const ByteArray *src)
{
    CryptoniteDigestParams *digest_params = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(da != NULL);
    CHECK_PARAM(src != NULL);

    digest_params = (CryptoniteDigestParams *)da->ctx;
    if (!digest_params) {
        SET_ERROR(RET_CONTEXT_NOT_READY);
    }

    if (digest_params->mode_id == DIGEST_MODE_GOST34311) {
        DO(gost34_311_update(digest_params->mode.gost, src));
    } else if (digest_params->mode_id == DIGEST_MODE_SHA1) {
        DO(sha1_update(digest_params->mode.sha1, src));
    } else if (digest_params->mode_id == DIGEST_MODE_SHA2) {
        DO(sha2_update(digest_params->mode.sha2, src));
    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

/** Вычисляет хеш-вектор от открытых данных.
 *
 * @param da адаптер хэширования
 * @param digest буфер для хеш-вектора
 *
 * @return код ошибки
 */
static int da_final(const DigestAdapter *da, ByteArray **digest)
{
    int ret = RET_OK;

    CryptoniteDigestParams *digest_params = NULL;

    LOG_ENTRY();

    CHECK_PARAM(da);
    CHECK_PARAM(digest);

    digest_params = (CryptoniteDigestParams *)da->ctx;

    if (digest_params->mode_id == DIGEST_MODE_GOST34311) {
        DO(gost34_311_final(digest_params->mode.gost, digest));
    } else if (digest_params->mode_id == DIGEST_MODE_SHA1) {
        DO(sha1_final(digest_params->mode.sha1, digest));
    } else if (digest_params->mode_id == DIGEST_MODE_SHA2) {
        DO(sha2_final(digest_params->mode.sha2, digest));
    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    return ret;
}

/**
 * Очищает контекст digest_adapter_t.
 *
 * @param da контекст
 */
static void da_free(DigestAdapter *da)
{
    CryptoniteDigestParams *digest_params;

    LOG_ENTRY();

    if (!da) {
        return;
    }

    da->update = NULL;
    da->final = NULL;
    da->get_alg = NULL;
    da->free = NULL;

    digest_params = (CryptoniteDigestParams *) da->ctx;

    if (digest_params) {
        if (digest_params->mode_id == DIGEST_MODE_GOST34311) {
            gost34_311_free(digest_params->mode.gost);
        } else if (digest_params->mode_id == DIGEST_MODE_SHA1) {
            sha1_free(digest_params->mode.sha1);
        } else if (digest_params->mode_id == DIGEST_MODE_SHA2) {
            sha2_free(digest_params->mode.sha2);
        }
        ASN_FREE(&AlgorithmIdentifier_desc, digest_params->digest_aid);
        free(digest_params);
    }

    free(da);
}

int digest_adapter_init_default(DigestAdapter **da)
{
    int ret = RET_OK;

    DigestAdapter *adapter = NULL;
    CryptoniteDigestParams *digest_parameters_str = NULL;
    ByteArray *sbox = NULL;
    ByteArray *sync = NULL;

    CHECK_PARAM(da);

    CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
    DO(ba_set(sync, 0));

    LOG_ENTRY();

    CALLOC_CHECKED(adapter, sizeof(DigestAdapter));

    adapter->update = da_update;
    adapter->final = da_final;
    adapter->get_alg = da_get_alg;
    adapter->free = da_free;

    CALLOC_CHECKED(digest_parameters_str, sizeof(CryptoniteDigestParams));

    DO(get_sbox_by_id(GOST28147_SBOX_ID_1, &sbox));
    CHECK_NOT_NULL(digest_parameters_str->mode.gost = gost34_311_alloc_user_sbox(sbox, sync));

    digest_parameters_str->mode_id = DIGEST_MODE_GOST34311;
    DO(aid_create_gost3411(&digest_parameters_str->digest_aid));

    *((void **)&adapter->ctx) = digest_parameters_str;
    *da = adapter;

cleanup:

    if (ret != RET_OK) {
        da_free(adapter);
    }
    ba_free(sbox);
    ba_free(sync);

    return ret;
}

int digest_adapter_init_by_aid(const AlgorithmIdentifier_t *aid, DigestAdapter **da)
{
    int ret = RET_OK;
    DigestAdapter *adapter = NULL;
    CryptoniteDigestParams *digest_parameters_str = NULL;
    ByteArray *sbox = NULL;
    ByteArray *sync = NULL;

    CHECK_PARAM(aid);
    CHECK_PARAM(da);

    CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
    DO(ba_set(sync, 0));

    LOG_ENTRY();

    CALLOC_CHECKED(adapter, sizeof(DigestAdapter));
    CALLOC_CHECKED(digest_parameters_str, sizeof(CryptoniteDigestParams));

    if (pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        DO(aid_create_gost3411(&digest_parameters_str->digest_aid));

        DO(get_sbox_from_aid(aid, &sbox));
        digest_parameters_str->mode_id = DIGEST_MODE_GOST34311;
        CHECK_NOT_NULL(digest_parameters_str->mode.gost = gost34_311_alloc_user_sbox(sbox, sync));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID))) {
        digest_parameters_str->mode_id = DIGEST_MODE_SHA1;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha1 = sha1_alloc());
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID), &digest_parameters_str->digest_aid->algorithm));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
        digest_parameters_str->mode_id = DIGEST_MODE_SHA2;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha2 = sha2_alloc(SHA2_VARIANT_224));
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID), &digest_parameters_str->digest_aid->algorithm));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
        digest_parameters_str->mode_id = DIGEST_MODE_SHA2;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha2 = sha2_alloc(SHA2_VARIANT_256));
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID), &digest_parameters_str->digest_aid->algorithm));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
        digest_parameters_str->mode_id = DIGEST_MODE_SHA2;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha2 = sha2_alloc(SHA2_VARIANT_384));
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID), &digest_parameters_str->digest_aid->algorithm));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID))
            || pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
        digest_parameters_str->mode_id = DIGEST_MODE_SHA2;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha2 = sha2_alloc(SHA2_VARIANT_512));
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID), &digest_parameters_str->digest_aid->algorithm));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_GOST3410_KZ_ID))) {
        CHECK_NOT_NULL(digest_parameters_str->mode.gost = gost34_311_alloc(GOST28147_SBOX_ID_11, sync));
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_GOST3410_KZ_ID), &digest_parameters_str->digest_aid->algorithm));
    } else {
        //Стандартное значение.
        digest_parameters_str->mode_id = DIGEST_MODE_SHA1;
        CHECK_NOT_NULL(digest_parameters_str->mode.sha1 = sha1_alloc());
        ASN_ALLOC(digest_parameters_str->digest_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID), &digest_parameters_str->digest_aid->algorithm));
    }

    adapter->update = da_update;
    adapter->final = da_final;
    adapter->get_alg = da_get_alg;
    adapter->free = da_free;

    *((void **) &adapter->ctx) = digest_parameters_str;
    *da = adapter;

cleanup:

    if (ret != RET_OK) {
        da_free(adapter);
    }
    ba_free(sbox);
    ba_free(sync);

    return ret;
}

int digest_adapter_init_by_cert(const Certificate_t *cert, DigestAdapter **da)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(da != NULL);

    if (pkix_check_oid_parent(&cert->signatureAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        DO(digest_adapter_init_by_aid(&cert->tbsCertificate.subjectPublicKeyInfo.algorithm, da));
    } else if (pkix_check_oid_equal(&cert->signatureAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
               pkix_check_oid_equal(&cert->signatureAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
               pkix_check_oid_equal(&cert->signatureAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
               pkix_check_oid_equal(&cert->signatureAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID)) ||
               pkix_check_oid_equal(&cert->signatureAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID))) {
        DO(digest_adapter_init_by_aid(&cert->signatureAlgorithm, da));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_OID);
    }

cleanup:

    return ret;
}

DigestAdapter *digest_adapter_copy_with_alloc(const DigestAdapter *da)
{
    DigestAdapter *adapter = NULL;
    CryptoniteDigestParams *params = NULL;
    CryptoniteDigestParams *ctx;
    int ret = RET_OK;

    CHECK_PARAM(da != NULL);

    CALLOC_CHECKED(adapter, sizeof(DigestAdapter));

    adapter->update = da->update;
    adapter->final = da->final;
    adapter->get_alg = da->get_alg;
    adapter->free = da->free;

    ctx = (CryptoniteDigestParams *)(da->ctx);
    CALLOC_CHECKED(params, sizeof(CryptoniteDigestParams));

    if (ctx->mode_id == DIGEST_MODE_GOST34311) {
        CHECK_NOT_NULL(params->mode.gost = gost34_311_copy_with_alloc(ctx->mode.gost));
    } else if (ctx->mode_id == DIGEST_MODE_SHA1) {
        CHECK_NOT_NULL(params->mode.sha1 = sha1_copy_with_alloc(ctx->mode.sha1));
    } else if (ctx->mode_id == DIGEST_MODE_SHA2) {
        CHECK_NOT_NULL(params->mode.sha2 = sha2_copy_with_alloc(ctx->mode.sha2));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

    params->mode_id = ctx->mode_id;
    CHECK_NOT_NULL(params->digest_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ctx->digest_aid));

    *((void **)&adapter->ctx) = params;

cleanup:

    if (ret != RET_OK) {
        digest_adapter_free(adapter);
        adapter = NULL;
    }

    return adapter;
}

static int cryptonite_cipher_params_init(CryptoniteCipherParams *cipher_params_struct)
{
    int ret = RET_OK;

    int i, j;
    int count;
    unsigned char *dke = NULL;
    size_t dke_size;
    unsigned char sbox[SBOX_SIZE] = {0};
    GOST28147ParamsOptionalDke_t *gost28147_params = NULL;
    OCTET_STRING_t *iv_oct_str = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cipher_params_struct != NULL);

    if (pkix_check_oid_parent(&cipher_params_struct->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_GOST28147_DSTU_ID))) {

        CHECK_NOT_NULL(gost28147_params = asn_any2type(cipher_params_struct->asn_cipher_aid->parameters,
                &GOST28147ParamsOptionalDke_desc));
        DO(asn_OCTSTRING2ba(&gost28147_params->iv, &cipher_params_struct->cipher_init_vector));
        CHECK_NOT_NULL(cipher_params_struct->cipher_init_vector);

        if (gost28147_params->dke != NULL) {
            DO(asn_OCTSTRING2bytes(gost28147_params->dke, &dke, &dke_size));

            count = 0;
            for (i = 0; i < 8; i++) {
                for (j = 0; j < 16; j++) {
                    sbox[count++] = (dke[(i << 3) + (j >> 1)] >> ((~j & 1) << 2)) & 0xf;
                }
            }

            CHECK_NOT_NULL(cipher_params_struct->sbox = ba_alloc_from_uint8(sbox, SBOX_SIZE));
        } else {
            DO(get_sbox_by_id(GOST28147_SBOX_ID_1, &cipher_params_struct->sbox));
        }
        CHECK_NOT_NULL(cipher_params_struct->sbox);

    } else if (pkix_check_oid_equal(&cipher_params_struct->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_AES256_CBC_ID))) {
        CHECK_NOT_NULL(iv_oct_str = asn_any2type(cipher_params_struct->asn_cipher_aid->parameters, &OCTET_STRING_desc));
        DO(asn_OCTSTRING2ba(iv_oct_str, &cipher_params_struct->cipher_init_vector));
        ret = RET_OK;
        goto cleanup;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_CIPHER_ALG);
    }

cleanup:

    free(dke);
    ASN_FREE(&GOST28147ParamsOptionalDke_desc, gost28147_params);
    ASN_FREE(&OCTET_STRING_desc, iv_oct_str);

    return ret;
}

/**
 * Зашифровывает открытые данные.
 *
 * @param ca адаптер шифрования
 * @param key секретный ключ
 * @param src открытые данные
 * @param dst буфер для шифротекста
 *
 * @return код ошибки
 */
static int ca_cipher_encrypt(const CipherAdapter *ca, const ByteArray *key, const ByteArray *src, ByteArray **dst)
{
    int ret = RET_OK;
    AesCtx *aes_ctx = NULL;
    Gost28147Ctx *params = NULL;
    CryptoniteCipherParams *cipher_params_str = NULL;
    ByteArray *src_with_padding = NULL;
    LOG_ENTRY();

    CHECK_PARAM(ca != NULL);
    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(ba_get_len(key) == 32);

    cipher_params_str = (CryptoniteCipherParams *)ca->ctx;

    if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID))) {
        CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(cipher_params_str->sbox));
        DO(gost28147_init_ctr(params, key, cipher_params_str->cipher_init_vector));
        DO(gost28147_encrypt(params, src, dst));
    } else if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID))) {
        CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(cipher_params_str->sbox));
        DO(gost28147_init_cfb(params, key, cipher_params_str->cipher_init_vector));
        DO(gost28147_encrypt(params, src, dst));
    } else if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_AES256_CBC_ID))) {
        CHECK_NOT_NULL(aes_ctx = aes_alloc());
        DO(aes_init_cbc(aes_ctx, key, cipher_params_str->cipher_init_vector));
        DO(make_pkcs7_padding(src, (uint8_t)ba_get_len(cipher_params_str->cipher_init_vector), &src_with_padding));
        DO(aes_encrypt(aes_ctx, src_with_padding, dst));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_CIPHER_ALG);
    }

cleanup:

    gost28147_free(params);
    aes_free(aes_ctx);
    ba_free(src_with_padding);

    return ret;
}

/**
 * Расшифровывает открытые данные.
 *
 * @param cа адаптер шифрования
 * @param key секретный ключ
 * @param src шифротекст
 * @param dst буфер для расшифрованного текста
 *
 * @return код ошибки
 */
static int ca_cipher_decrypt(const CipherAdapter *ca, const ByteArray *key, const ByteArray *src, ByteArray **dst)
{
    int ret = RET_OK;

    AesCtx *aes_params = NULL;
    Gost28147Ctx *gost_params = NULL;
    CryptoniteCipherParams *cipher_params_str = NULL;
    ByteArray *dst_with_padding = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ca != NULL);
    CHECK_PARAM(src != NULL);
    CHECK_PARAM(dst != NULL);
    CHECK_PARAM(ca->ctx != NULL);
    CHECK_PARAM(key != NULL);
    CHECK_PARAM((ba_get_len(key) == 32));

    cipher_params_str = (CryptoniteCipherParams *)ca->ctx;

    if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID))) {

        CHECK_NOT_NULL(gost_params = gost28147_alloc_user_sbox(cipher_params_str->sbox));
        DO(gost28147_init_ctr(gost_params, key, cipher_params_str->cipher_init_vector));
        DO(gost28147_decrypt(gost_params, src, dst));

    } else if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID))) {

        CHECK_NOT_NULL(gost_params = gost28147_alloc_user_sbox(cipher_params_str->sbox));
        DO(gost28147_init_cfb(gost_params, key, cipher_params_str->cipher_init_vector));
        DO(gost28147_decrypt(gost_params, src, dst));

    } else if (pkix_check_oid_parent(&cipher_params_str->asn_cipher_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_AES256_CBC_ID))) {
        CHECK_NOT_NULL(aes_params = aes_alloc());
        DO(aes_init_cbc(aes_params, key, cipher_params_str->cipher_init_vector));
        DO(aes_decrypt(aes_params, src, &dst_with_padding));
        DO(make_pkcs7_unpadding(dst_with_padding, dst));

    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_CIPHER_ALG);
    }


cleanup:

    gost28147_free(gost_params);
    aes_free(aes_params);
    ba_free(dst_with_padding);

    return ret;
}

/**
 * Возвращает алгоритм шифрования в виде ASN1 структуры.
 *
 * @param cа адаптер шифрования
 * @param alg_id буфер для размещения ASN1 структуры алгоритма шифрования
 *
 * @return код ошибки
 */
static int ca_cipher_get_aid(const CipherAdapter *ca, AlgorithmIdentifier_t **alg_id)
{
    int ret = RET_OK;
    CryptoniteCipherParams *cipher_params_str = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ca != NULL);
    CHECK_PARAM(ca->ctx != NULL);
    CHECK_PARAM(alg_id != NULL);

    cipher_params_str = (CryptoniteCipherParams *)ca->ctx;

    CHECK_NOT_NULL(*alg_id = asn_copy_with_alloc(&AlgorithmIdentifier_desc, cipher_params_str->asn_cipher_aid));

cleanup:

    return ret;
}

/**
 * Очищает контекст cipher_adapter_t.
 *
 * @param ca контекст
 */
static void ca_free(CipherAdapter *ca)
{
    CryptoniteCipherParams *gcp;

    LOG_ENTRY();

    if (!ca) {
        return;
    }

    ca->encrypt = NULL;
    ca->decrypt = NULL;
    ca->get_alg = NULL;
    ca->free = NULL;

    gcp = (CryptoniteCipherParams *)ca->ctx;

    if (gcp) {
        ASN_FREE(&AlgorithmIdentifier_desc, gcp->asn_cipher_aid);
        ba_free(gcp->sbox);
        ba_free(gcp->cipher_init_vector);
        free(gcp);
    }

    free(ca);
}

void cipher_adapter_free(CipherAdapter *ca)
{
    if (ca) {
        ca->free(ca);
    }
}

int cipher_adapter_init(const AlgorithmIdentifier_t *alg_id, CipherAdapter **ca)
{
    int ret = RET_OK;
    CryptoniteCipherParams *cipher_params_str = NULL;
    CipherAdapter *adapter = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ca != NULL);
    CHECK_PARAM(alg_id != NULL);

    CALLOC_CHECKED(adapter, sizeof(CipherAdapter));

    adapter->encrypt = ca_cipher_encrypt;
    adapter->decrypt = ca_cipher_decrypt;
    adapter->get_alg = ca_cipher_get_aid;
    adapter->free = ca_free;

    CALLOC_CHECKED(cipher_params_str, sizeof(CryptoniteCipherParams));

    CHECK_NOT_NULL(cipher_params_str->asn_cipher_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, alg_id));

    DO(cryptonite_cipher_params_init(cipher_params_str));

    *((void **)&adapter->ctx) = cipher_params_str;

    *ca = adapter;
    adapter = NULL;

cleanup:

    ca_free(adapter);

    return ret;
}

CipherAdapter *cipher_adapter_copy_with_alloc(const CipherAdapter *ca)
{
    CipherAdapter *adapter = NULL;
    CryptoniteCipherParams *ca_ctx = NULL;
    CryptoniteCipherParams *params = NULL;
    int ret = RET_OK;

    CHECK_PARAM(ca != NULL);

    CALLOC_CHECKED(adapter, sizeof(CipherAdapter));

    adapter->encrypt = ca->encrypt;
    adapter->decrypt = ca->decrypt;
    adapter->get_alg = ca->get_alg;
    adapter->free = ca->free;

    ca_ctx = (CryptoniteCipherParams *)(ca->ctx);

    CALLOC_CHECKED(params, sizeof(CryptoniteCipherParams));

    CHECK_NOT_NULL(params->asn_cipher_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ca_ctx->asn_cipher_aid));
    CHECK_NOT_NULL(params->sbox = ba_copy_with_alloc(ca_ctx->sbox, 0, 0));
    CHECK_NOT_NULL(params->cipher_init_vector = ba_copy_with_alloc(ca_ctx->cipher_init_vector, 0, 0));

    *((void **)&adapter->ctx) = params;

cleanup:

    if (ret != RET_OK) {
        cipher_adapter_free(adapter);
        adapter = NULL;
    }

    return adapter;
}

/**
 * Инициализирует ASN1-параметры для алгоритмов подписи/проверки.
 *
 * @param sign_parameters_str указатель на структуру глобальных параметров
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_asn_init(CryptoniteSignParams *sign_parameters_str)
{
    int ret = RET_OK;
    void *params_buf = NULL;

    LOG_ENTRY();
    CHECK_PARAM(sign_parameters_str != NULL);

    if (pkix_check_oid_parent(&sign_parameters_str->signature_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        sign_parameters_str->alg_marker = DSTU4145;
        CHECK_NOT_NULL(params_buf = asn_any2type(sign_parameters_str->params_aid->parameters, &DSTU4145Params_desc));
        ASN_FREE(&DSTU4145Params_desc, sign_parameters_str->asn_dstu_params);
        sign_parameters_str->asn_dstu_params = params_buf;

    } else if (pkix_check_oid_equal(&sign_parameters_str->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
            pkix_check_oid_equal(&sign_parameters_str->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
            pkix_check_oid_equal(&sign_parameters_str->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
            pkix_check_oid_equal(&sign_parameters_str->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID)) ||
            pkix_check_oid_equal(&sign_parameters_str->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID))) {

        sign_parameters_str->alg_marker = ECDSA;
        CHECK_NOT_NULL(params_buf = asn_any2type(sign_parameters_str->params_aid->parameters, &ECParameters_desc));
        ASN_FREE(&ECParameters_desc, sign_parameters_str->asn_ec_params);
        sign_parameters_str->asn_ec_params = params_buf;

    } else {
        sign_parameters_str->alg_marker = WRONG_ID;
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    return ret;
}

/**
 * Очищает контекст cryptonite_sign_params_t.
 *
 * @param sign_parameters_str контекст
 */
static void cryptonite_sign_params_free(CryptoniteSignParams *sign_parameters_str)
{
    LOG_ENTRY();

    if (sign_parameters_str) {
        ba_free_private(sign_parameters_str->private_key);
        ba_free(sign_parameters_str->digest_sbox);

        aid_free(sign_parameters_str->digest_aid);
        aid_free(sign_parameters_str->signature_aid);
        aid_free(sign_parameters_str->params_aid);
        cert_free(sign_parameters_str->certificate);

        ASN_FREE(&BIT_STRING_desc, sign_parameters_str->public_key);
        ASN_FREE(&DSTU4145Params_desc, sign_parameters_str->asn_dstu_params);
        ASN_FREE(&ECParameters_desc, sign_parameters_str->asn_ec_params);

        switch (sign_parameters_str->alg_marker) {
        case DSTU4145:
            dstu4145_free(sign_parameters_str->alg_type.dstu);
            break;
        case ECDSA:
            ecdsa_free(sign_parameters_str->alg_type.ecdsa);
            break;
        default:
            break;
        }


        prng_free(sign_parameters_str->prng_ctx);

        free(sign_parameters_str);
    }
}

/**
 * Инициализирует Cryptonite параметры алгоритмов подписи/проверки.
 *
 * @param sign_parameters_str указатель на структуру глобальных параметров
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_init(CryptoniteSignParams *sign_parameters_str)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sign_parameters_str != NULL);

    if (sign_parameters_str->alg_marker == DSTU4145 && sign_parameters_str->alg_type.dstu) {
        dstu4145_free(sign_parameters_str->alg_type.dstu);
        sign_parameters_str->alg_type.dstu = NULL;
    }
    if (sign_parameters_str->alg_marker == ECDSA && sign_parameters_str->alg_type.ecdsa) {
        ecdsa_free(sign_parameters_str->alg_type.ecdsa);
        sign_parameters_str->alg_type.ecdsa = NULL;
    }

    ba_free(sign_parameters_str->digest_sbox);
    sign_parameters_str->digest_sbox = NULL;

    prng_free(sign_parameters_str->prng_ctx);
    sign_parameters_str->prng_ctx = NULL;

    if (sign_parameters_str->alg_marker == DSTU4145) {
        DO(aid_get_dstu4145_params(sign_parameters_str->params_aid, &sign_parameters_str->alg_type.dstu));

        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(rs_std_next_bytes(seed));
        CHECK_NOT_NULL(sign_parameters_str->prng_ctx = prng_alloc(PRNG_MODE_DEFAULT, seed));

        DO(get_sbox_from_aid(sign_parameters_str->params_aid, &sign_parameters_str->digest_sbox));

    } else if (sign_parameters_str->alg_marker == ECDSA) {
        DO(aid_get_ecdsa_params(sign_parameters_str->params_aid, &sign_parameters_str->alg_type.ecdsa));

        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(rs_std_next_bytes(seed));
        CHECK_NOT_NULL(sign_parameters_str->prng_ctx = prng_alloc(PRNG_MODE_DEFAULT, seed));
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    if (ret != RET_OK) {
        cryptonite_sign_params_free(sign_parameters_str);
    }
    ba_free(seed);

    return ret;
}

/**
 * Формирует ЭЦП сообщение.
 *
 * @param sa адаптер формирования подписи
 * @param data данные, которые необходимо подписать
 * @param sign буфер для подписи
 *
 * @return код ошибки
 */
static int sa_sign_data(const SignAdapter *sa, const ByteArray *data, ByteArray **sign)
{
    int ret = RET_OK;

    ByteArray *digest_to_sign = NULL;
    ByteArray *seed = NULL;
    Gost34311Ctx *digest_ctx = NULL;
    Sha2Ctx *sha2_ctx = NULL;
    Sha1Ctx *sha1_ctx = NULL;
    ByteArray *sync = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    PrngCtx *prng = NULL;
    DigestAlgorithmIdentifier_t *daid = NULL;
    CryptoniteSignParams *sign_parameters_str = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(sign != NULL);

    sign_parameters_str = (CryptoniteSignParams *)sa->ctx;

    if (sign_parameters_str->alg_marker == DSTU4145) {
        CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
        DO(ba_set(sync, 0));
        CHECK_NOT_NULL(digest_ctx = gost34_311_alloc_user_sbox(sign_parameters_str->digest_sbox, sync));
        DO(gost34_311_update(digest_ctx, data));
        DO(gost34_311_final(digest_ctx, &digest_to_sign));

        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(prng_next_bytes(sign_parameters_str->prng_ctx, seed));
        CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

        DO(dstu4145_init_sign(sign_parameters_str->alg_type.dstu,
                sign_parameters_str->private_key, prng));

        DO(dstu4145_sign(sign_parameters_str->alg_type.dstu, digest_to_sign, &r, &s));
        *sign = ba_join(r, s);
    } else  if (sign_parameters_str->alg_marker == ECDSA) {
        DO(sa->get_digest_alg(sa, &daid));
        if (!pkix_check_oid_equal(&daid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {
            if (pkix_check_oid_equal(&daid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
                CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_224));
            } else if (pkix_check_oid_equal(&daid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
                CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_256));
            } else if (pkix_check_oid_equal(&daid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
                CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_384));
            } else if (pkix_check_oid_equal(&daid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
                CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_512));
            }
            DO(sha2_update(sha2_ctx, data));
            DO(sha2_final(sha2_ctx, &digest_to_sign));
        } else {
            CHECK_NOT_NULL(sha1_ctx = sha1_alloc());
            DO(sha1_update(sha1_ctx, data));
            DO(sha1_final(sha1_ctx, &digest_to_sign));
        }
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(prng_next_bytes(sign_parameters_str->prng_ctx, seed));
        CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));

        DO(ecdsa_init_sign(sign_parameters_str->alg_type.ecdsa,
                sign_parameters_str->private_key,
                prng));
        DO(ecdsa_sign(sign_parameters_str->alg_type.ecdsa, digest_to_sign, &r, &s));
        ba_swap(r);
        ba_swap(s);
        CHECK_NOT_NULL(*sign = ba_join(r, s));

    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    aid_free(daid);
    ba_free(digest_to_sign);
    ba_free(sync);
    ba_free(seed);
    ba_free(r);
    ba_free(s);
    prng_free(prng);
    sha2_free(sha2_ctx);
    gost34_311_free(digest_ctx);

    return ret;
}

static int sa_sign_hash(const SignAdapter *sa, const ByteArray *hash, ByteArray **sign)
{
    int ret = RET_OK;
    ByteArray *seed = NULL;
    CryptoniteSignParams *sign_parameters_str = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    PrngCtx *prng = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    sign_parameters_str = (CryptoniteSignParams *)sa->ctx;

    if (sign_parameters_str->alg_marker == DSTU4145) {

        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        prng_next_bytes(sign_parameters_str->prng_ctx, seed);
        CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

        DO(dstu4145_init_sign(sign_parameters_str->alg_type.dstu,
                sign_parameters_str->private_key,
                prng));

        DO(dstu4145_sign(sign_parameters_str->alg_type.dstu, hash, &r, &s));
        CHECK_NOT_NULL(*sign = ba_join(r, s));
    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    ba_free(seed);
    ba_free(r);
    ba_free(s);

    prng_free(prng);

    return ret;
}

/**
 * Проверяет корректность ЭЦП сообщения.
 *
 * @param va адаптер проверки подписи
 * @param hash
 * @param sign подпись
 *
 * @return код ошибки
 */
static int va_verify_hash(const VerifyAdapter *va, const ByteArray *hash, const ByteArray *sign)
{
    int ret = RET_OK;

    ByteArray *compressed_buffer = NULL;

    ByteArray *compressed_public_key = NULL;
    ByteArray *dstu_public_x = NULL;
    ByteArray *dstu_public_y = NULL;

    BIT_STRING_t *pub_key_bs = NULL;
    INTEGER_t *integer_public = NULL;
    OCTET_STRING_t *octet_public = NULL;

    CryptoniteSignParams *sign_parameters_str = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(sign != NULL);

    sign_parameters_str = (CryptoniteSignParams *)va->ctx;

    if (sign_parameters_str->alg_marker == DSTU4145) {
        CHECK_NOT_NULL(pub_key_bs = asn_copy_with_alloc(&BIT_STRING_desc, sign_parameters_str->public_key));
        DO(asn_BITSTRING2ba(pub_key_bs, &compressed_buffer));

        CHECK_NOT_NULL(octet_public = asn_decode_ba_with_alloc(&OCTET_STRING_desc, compressed_buffer));

        DO(asn_OCTSTRING2ba(octet_public, &compressed_public_key));

        if (!is_dstu_le_params(&sign_parameters_str->params_aid->algorithm)) {
            DO(ba_swap(compressed_public_key));
        }

        DO(dstu4145_decompress_pubkey(sign_parameters_str->alg_type.dstu, compressed_public_key, &dstu_public_x,
                &dstu_public_y));
        DO(dstu4145_init_verify(sign_parameters_str->alg_type.dstu, dstu_public_x, dstu_public_y));

        CHECK_NOT_NULL(r = ba_copy_with_alloc(sign, 0, ba_get_len(sign) / 2));
        CHECK_NOT_NULL(s = ba_copy_with_alloc(sign, ba_get_len(sign) / 2, 0));

        DO(dstu4145_verify(sign_parameters_str->alg_type.dstu, hash, r, s));

    } else if (sign_parameters_str->alg_marker == ECDSA) {
        CHECK_NOT_NULL(pub_key_bs = asn_copy_with_alloc(&BIT_STRING_desc, sign_parameters_str->public_key));
        DO(asn_BITSTRING2ba(pub_key_bs, &compressed_buffer));
        CHECK_NOT_NULL(compressed_buffer);
        //Проверяем, какого типа пришла подпись 0x04 - несжатая форма, 0х03 - сжатая форма, последний бит 1, 0х02 - сжатая форма, последний бит 0
        if (ba_get_buf(compressed_buffer)[0] == 0x04) {
            DO(ba_swap(compressed_buffer));
            DO(ba_change_len(compressed_buffer, ba_get_len(compressed_buffer) - 1));
            DO(ba_swap(compressed_buffer));
            CHECK_NOT_NULL(qx = ba_copy_with_alloc(compressed_buffer, 0, (ba_get_len(compressed_buffer) >> 1)));
            CHECK_NOT_NULL(qy = ba_copy_with_alloc(compressed_buffer, (ba_get_len(compressed_buffer) >> 1), 0));

            //Открытый ключ в формате be
            DO(ba_swap(qx));
            DO(ba_swap(qy));

        } else if (ba_get_buf(compressed_buffer)[0] == 0x02 || ba_get_buf(compressed_buffer)[0] == 0x03) {
            //Переводим в ле формат.
            DO(ba_swap(compressed_buffer));
            DO(ba_change_len(compressed_buffer, ba_get_len(compressed_buffer) - 1));
            DO(ecdsa_decompress_pubkey(sign_parameters_str->alg_type.ecdsa, compressed_buffer, ba_get_buf(compressed_buffer)[0] - 2,
                    &qx, &qy));
        } else {
            SET_ERROR(RET_UNSUPPORTED_ECDSA_PARAMS);
        }

        size_t ba_len = ba_get_len(sign) >> 1;

        CHECK_NOT_NULL(r = ba_copy_with_alloc(sign, 0, ba_len + (ba_get_len(sign) % 2)));
        CHECK_NOT_NULL(s = ba_copy_with_alloc(sign, ba_len + (ba_get_len(sign) % 2), 0));

        DO(ecdsa_init_verify(sign_parameters_str->alg_type.ecdsa, qx, qy));
        DO(ecdsa_verify(sign_parameters_str->alg_type.ecdsa, hash, r, s));

    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

cleanup:

    ba_free(dstu_public_x);
    ba_free(dstu_public_y);
    ba_free(compressed_public_key);
    ba_free(r);
    ba_free(s);
    ba_free(qx);
    ba_free(qy);

    ba_free(compressed_buffer);

    ASN_FREE(&BIT_STRING_desc, pub_key_bs);
    ASN_FREE(&INTEGER_desc, integer_public);
    ASN_FREE(&OCTET_STRING_desc, octet_public);

    return ret;
}

/**
 * Проверяет корректность ЭЦП сообщения.
 *
 * @param va адаптер проверки подписи
 * @param data данные, которые были подписаны
 * @param sign подпись
 *
 * @return код ошибки
 */
static int va_verify_data(const VerifyAdapter *va, const ByteArray *data, const ByteArray *sign)
{
    int ret = RET_OK;

    ByteArray *hash = NULL;
    ByteArray *sync = NULL;
    CryptoniteSignParams *sign_parameters_str = NULL;
    Gost34311Ctx *digest_ctx = NULL;
    Sha2Ctx *sha2_ctx = NULL;
    Sha1Ctx *sha1_ctx = NULL;

    LOG_ENTRY();

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(sign != NULL);

    sign_parameters_str = (CryptoniteSignParams *)va->ctx;

    if (sign_parameters_str->alg_marker == DSTU4145) {
        CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
        DO(ba_set(sync, 0));
        CHECK_NOT_NULL(digest_ctx = gost34_311_alloc_user_sbox(sign_parameters_str->digest_sbox, sync));
        DO(gost34_311_update(digest_ctx, data));
        DO(gost34_311_final(digest_ctx, &hash));

    } else if (sign_parameters_str->alg_marker == ECDSA) {
        if (pkix_check_oid_equal(&sign_parameters_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
            CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_224));
        } else if (pkix_check_oid_equal(&sign_parameters_str->digest_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
            CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_256));
        } else if (pkix_check_oid_equal(&sign_parameters_str->digest_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
            CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_384));
        } else if (pkix_check_oid_equal(&sign_parameters_str->digest_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
            CHECK_NOT_NULL(sha2_ctx = sha2_alloc(SHA2_VARIANT_512));
        }

        if (sha2_ctx != NULL) {
            DO(sha2_update(sha2_ctx, data));
            DO(sha2_final(sha2_ctx, &hash));
        } else {
            //Default SHA1
            CHECK_NOT_NULL(sha1_ctx = sha1_alloc());
            DO(sha1_update(sha1_ctx, data));
            DO(sha1_final(sha1_ctx, &hash));
        }

    } else {
        SET_ERROR(RET_PKIX_INVALID_CTX_MODE);
    }

    DO(va_verify_hash(va, hash, sign));

cleanup:

    ba_free(hash);
    ba_free(sync);
    gost34_311_free(digest_ctx);
    sha2_free(sha2_ctx);

    return ret;
}

/**
 * Возвращает объект открытого ключа, который был передан ранее.
 *
 * @param sign_params_str указатель на структуру глобальных параметров
 * @param info буфер для объекта открытого ключа
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_get_pub_key(const CryptoniteSignParams *sign_params_str,
        SubjectPublicKeyInfo_t **info)
{
    int ret = RET_OK;

    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *pubkey = NULL;
    BIT_STRING_t *pubkey_bs = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;

    LOG_ENTRY();

    CHECK_PARAM(info != NULL);

    ASN_ALLOC(spki);
    DO(asn_copy(&AlgorithmIdentifier_desc, sign_params_str->params_aid, &spki->algorithm));

    if (sign_params_str->public_key) {
        DO(asn_copy(&BIT_STRING_desc, sign_params_str->public_key, &spki->subjectPublicKey));
    } else {
        if (sign_params_str->alg_marker == DSTU4145) {
            DO(dstu4145_get_pubkey(sign_params_str->alg_type.dstu, sign_params_str->private_key, &qx, &qy));
            DO(dstu4145_compress_pubkey(sign_params_str->alg_type.dstu, qx, qy, &pubkey));
            DO(convert_pubkey_bytes_to_bitstring(&sign_params_str->params_aid->algorithm, pubkey, &pubkey_bs));
            DO(asn_copy(&BIT_STRING_desc, pubkey_bs, &spki->subjectPublicKey));
        }
        if (sign_params_str->alg_marker == ECDSA) {
            DO(ecdsa_get_pubkey(sign_params_str->alg_type.ecdsa, sign_params_str->private_key, &qx, &qy));
            CHECK_NOT_NULL(pubkey = ba_alloc_by_len(1));
            DO(ba_set(pubkey, 0x04));
            DO(ba_swap(qx));
            DO(ba_swap(qy));
            DO(ba_append(qx, 0, 0, pubkey));
            DO(ba_append(qy, 0, 0, pubkey));
            DO(asn_create_bitstring_from_ba(pubkey, &pubkey_bs));
            DO(asn_copy(&BIT_STRING_desc, pubkey_bs, &spki->subjectPublicKey));
        }
    }

    *info = spki;
    spki = NULL;

cleanup:

    spki_free(spki);
    ba_free(qx);
    ba_free(qy);
    ba_free(pubkey);
    ASN_FREE(&BIT_STRING_desc, pubkey_bs);

    return ret;
}

/**
* Возвращает объект открытого ключа, который был передан ранее.
*
* @param sa адаптер формирования подписи
* @param info буфер для объекта открытого ключа
*
* @return код ошибки
*/
static int sa_get_pub_key(const SignAdapter *sa, SubjectPublicKeyInfo_t **info)
{
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(info != NULL);

    ret =  cryptonite_sign_params_get_pub_key((CryptoniteSignParams *)sa->ctx, info);

cleanup:

    return ret;
}

static int va_get_pub_key(const VerifyAdapter *va, SubjectPublicKeyInfo_t **info)
{
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(info != NULL);

    ret = cryptonite_sign_params_get_pub_key((CryptoniteSignParams *)va->ctx, info);

cleanup:

    return ret;
}

static int check_cert_corresponding(const CryptoniteSignParams *sign_params_str, const Certificate_t *cert)
{
    int ret = RET_OK;
    SubjectPublicKeyInfo_t *info = NULL;

    if (sign_params_str->certificate != NULL) {
        if (!asn_equals(&Certificate_desc, sign_params_str->certificate, cert)) {
            SET_ERROR(RET_PKIX_NO_CERTIFICATE);
        } else {
            goto cleanup;
        }
    }

    if (sign_params_str->signature_aid != NULL
            && !asn_equals(&OBJECT_IDENTIFIER_desc, &sign_params_str->signature_aid->algorithm,
                    &cert->tbsCertificate.signature.algorithm)) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }

    DO(cryptonite_sign_params_get_pub_key(sign_params_str, &info));

    /* XXX: Параметры могут оказаться в различных представлениях: сжатом, разжатом
    if (sign_params_str->params_aid != NULL && !asn_equals(&AlgorithmIdentifier_desc, sign_params_str->params_aid, &cert->tbsCertificate.subjectPublicKeyInfo.algorithm)) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }
    */

    if (!asn_equals(&BIT_STRING_desc, &info->subjectPublicKey,
            &cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey)) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }

cleanup:

    spki_free(info);

    return ret;
}

/**
 * Устанавливает сертификат.
 *
 * @param sign_params_str указатель на структуру глобальных параметров
 * @param cert сертификат
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_set_cert(CryptoniteSignParams *sign_params_str, const Certificate_t *cert)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);

    DO(check_cert_corresponding(sign_params_str, cert));

    if (sign_params_str->signature_aid) {
        ASN_FREE(&AlgorithmIdentifier_desc, sign_params_str->signature_aid);
        sign_params_str->signature_aid = NULL;
    }

    CHECK_NOT_NULL(sign_params_str->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.signature));

    if (sign_params_str->certificate) {
        cert_free(sign_params_str->certificate);
        sign_params_str->certificate = NULL;
    }

    CHECK_NOT_NULL(sign_params_str->certificate = asn_copy_with_alloc(&Certificate_desc, cert));
    sign_params_str->has_cert = true;

    if (sign_params_str->params_aid) {
        ASN_FREE(&AlgorithmIdentifier_desc, sign_params_str->params_aid);
        sign_params_str->params_aid = NULL;
    }

    CHECK_NOT_NULL(sign_params_str->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.subjectPublicKeyInfo.algorithm));

    if (sign_params_str->public_key) {
        ASN_FREE(&BIT_STRING_desc, sign_params_str->public_key);
        sign_params_str->public_key = NULL;
    }

    CHECK_NOT_NULL(sign_params_str->public_key = asn_copy_with_alloc(&BIT_STRING_desc,
            &cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey));

    DO(cryptonite_sign_params_asn_init(sign_params_str));
    DO(cryptonite_sign_params_init(sign_params_str));

cleanup:

    return ret;
}

static int sa_set_digest_alg(SignAdapter *sa, const DigestAlgorithmIdentifier_t *da_id)
{
    OidId hash_checker = 0;
    int ret = RET_OK;
    CryptoniteSignParams *sign_params = NULL;

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(da_id != NULL);

    if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        hash_checker = OID_PKI_GOST3411_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {
        hash_checker = OID_PKI_SHA1_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
        hash_checker = OID_PKI_SHA224_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
        hash_checker = OID_PKI_SHA256_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
        hash_checker = OID_PKI_SHA384_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
        hash_checker = OID_PKI_SHA512_ID;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

    sign_params = (CryptoniteSignParams *)sa->ctx;

    if (sign_params->digest_aid) {
        ASN_FREE(&DigestAlgorithmIdentifier_desc, sign_params->digest_aid);
        sign_params->digest_aid = NULL;
    }
    CHECK_NOT_NULL(sign_params->digest_aid = asn_copy_with_alloc(&DigestAlgorithmIdentifier_desc, da_id));

    if (sign_params->signature_aid) {
        if (pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID))) {

            ASN_FREE_CONTENT_PTR(&DigestAlgorithmIdentifier_desc, sign_params->signature_aid);

            switch (hash_checker) {
            case OID_PKI_SHA1_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA224_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA256_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA384_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA512_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID), &sign_params->signature_aid->algorithm));
                break;
            default:
                SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
            }
        } else if (pkix_check_oid_equal(&sign_params->signature_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
            if (!pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
                SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
            }
        } else {
            SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
        }
    }

cleanup:

    return ret;
}

static int va_set_digest_alg(VerifyAdapter *va, const DigestAlgorithmIdentifier_t *da_id)
{
    OidId hash_checker = 0;
    int ret = RET_OK;
    CryptoniteSignParams *sign_params = NULL;

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(da_id != NULL);

    if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        hash_checker = OID_PKI_GOST3411_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {
        hash_checker = OID_PKI_SHA1_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
        hash_checker = OID_PKI_SHA224_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
        hash_checker = OID_PKI_SHA256_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
        hash_checker = OID_PKI_SHA384_ID;
    } else if (pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
        hash_checker = OID_PKI_SHA512_ID;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

    sign_params = (CryptoniteSignParams *)va->ctx;

    if (sign_params->digest_aid) {
        ASN_FREE(&DigestAlgorithmIdentifier_desc, sign_params->digest_aid);
        sign_params->digest_aid = NULL;
    }
    CHECK_NOT_NULL(sign_params->digest_aid = asn_copy_with_alloc(&DigestAlgorithmIdentifier_desc, da_id));

    if (sign_params->signature_aid) {
        if (pkix_check_oid_equal(&sign_params->signature_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
                pkix_check_oid_equal(&sign_params->signature_aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID))) {

            ASN_FREE(&DigestAlgorithmIdentifier_desc, sign_params->signature_aid);
            ASN_ALLOC(sign_params->signature_aid);

            switch (hash_checker) {
            case OID_PKI_SHA1_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA224_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA256_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA384_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID), &sign_params->signature_aid->algorithm));
                break;
            case OID_PKI_SHA512_ID:
                DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID), &sign_params->signature_aid->algorithm));
                break;
            default:
                SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
            }
        } else if (pkix_check_oid_equal(&sign_params->signature_aid->algorithm,
                oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
            if (!pkix_check_oid_equal(&da_id->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
                SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
            }
        } else {
            SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
        }
    }

cleanup:
    return ret;
}
/**
* Устанавливает сертификат.
*
* param sa адаптер формирования подписи
* @param cert сертификат
*
* @return код ошибки
*/
static int sa_set_cert(SignAdapter *sa, const Certificate_t *cert)
{
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(cert != NULL);

    ret = cryptonite_sign_params_set_cert((CryptoniteSignParams *)sa->ctx, cert);

cleanup:

    return ret;
}

static int va_set_cert(const VerifyAdapter *va, const Certificate_t *cert)
{
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(cert != NULL);

    ret = cryptonite_sign_params_set_cert((CryptoniteSignParams *)va->ctx, cert);

cleanup:

    return ret;
}

/**
 * Возвращает сертификат, который был передан ранее.
 *
 * @param sign_params_str указатель на структуру глобальных параметров
 * @param cert буфер для сертификата
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_get_cert(CryptoniteSignParams *sign_params_str, Certificate_t **cert)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);

    if (!sign_params_str->certificate) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    } else {
        CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&Certificate_desc, sign_params_str->certificate));
    }

cleanup:

    return ret;
}

/**
* Возвращает сертификат, который был передан ранее.
*
* @param sa адаптер формирования подписи
* @param cert буфер для сертификата
*
* @return код ошибки
*/
static int sa_get_cert(const SignAdapter *sa, Certificate_t **cert)
{
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(cert != NULL);

    DO(cryptonite_sign_params_get_cert((CryptoniteSignParams *)sa->ctx, cert));

cleanup:

    return ret;
}

static int va_get_cert(const VerifyAdapter *va, Certificate_t **cert)
{
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(cert != NULL);

    DO(cryptonite_sign_params_get_cert((CryptoniteSignParams *)va->ctx, cert));

cleanup:

    return ret;
}


/**
 * Проверяет, был ли передан сертификат.
 *
 * @param sa адаптер формирования подписи
 * @param has_cert результат проверки: 1 - передан, 0 - не передан
 *
 * @return код ошибки
 */
static int sa_has_cert(const SignAdapter *sa, bool *has_cert)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(has_cert != NULL);

    *has_cert = ((CryptoniteSignParams *)sa->ctx)->has_cert;

cleanup:

    return ret;
}

static int va_has_cert(const VerifyAdapter *va, bool *has_cert)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(has_cert != NULL);

    *has_cert = ((CryptoniteSignParams *)va->ctx)->has_cert;

cleanup:

    return ret;
}
/**
 * Возвращает текущий идентификатор хеш алгоритма.
 *
 * @param sign_params_str указатель на структуру глобальных параметров
 * @param digest_alg_id буфер для идентификатора хеш алгоритма
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_get_digest_aid(CryptoniteSignParams *sign_params_str,
        DigestAlgorithmIdentifier_t **digest_alg_id)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(digest_alg_id != NULL);

    if (!sign_params_str->params_aid) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CONTEXT_NOT_READY);
    }

    if (pkix_check_oid_parent(&sign_params_str->params_aid->algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        DO(aid_create_gost3411(digest_alg_id));
    } else if (pkix_check_oid_equal(&sign_params_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))
            || pkix_check_oid_equal(&sign_params_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))
            || pkix_check_oid_equal(&sign_params_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))
            || pkix_check_oid_equal(&sign_params_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))
            || pkix_check_oid_equal(&sign_params_str->digest_aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {

        CHECK_NOT_NULL(*digest_alg_id = asn_copy_with_alloc(&AlgorithmIdentifier_desc, sign_params_str->digest_aid));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

cleanup:

    return ret;
}

/**
* Возвращает текущий идентификатор хеш алгоритма.
*
* @param sa адаптер формирования подписи
* @param digest_alg_id буфер для идентификатора хеш алгоритма
*
* @return код ошибки
*/
static int sa_get_digest_aid(const SignAdapter *sa, DigestAlgorithmIdentifier_t **digest_alg_id)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(digest_alg_id != NULL);

    ret = cryptonite_sign_params_get_digest_aid((CryptoniteSignParams *)sa->ctx, digest_alg_id);

cleanup:

    return ret;
}

static int va_get_digest_aid(const VerifyAdapter *va, DigestAlgorithmIdentifier_t **digest_alg_id)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(digest_alg_id != NULL);

    ret = cryptonite_sign_params_get_digest_aid((CryptoniteSignParams *)va->ctx, digest_alg_id);

cleanup:

    return ret;
}

/**
 * Возвращает текущий идентификатор алгоритма подписи.
 *
 * @param sign_params_str указатель на структуру глобальных параметров
 * @param sign_alg_id буфер для идентификатора алгоритма подписи
 *
 * @return код ошибки
 */
static int cryptonite_sign_params_get_sign_aid(CryptoniteSignParams *sign_params_str,
        SignatureAlgorithmIdentifier_t **sign_alg_id)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sign_alg_id != NULL);

    if (!sign_params_str->signature_aid) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CONTEXT_NOT_READY);
    }

    CHECK_NOT_NULL(*sign_alg_id = asn_copy_with_alloc(&SignatureAlgorithmIdentifier_desc, sign_params_str->signature_aid));

cleanup:

    return ret;
}

/**
* Возвращает текущий идентификатор алгоритма подписи.
*
* @param sa адаптер формирования подписи
* @param sign_alg_id буфер для идентификатора алгоритма подписи
*
* @return код ошибки
*/
static int sa_get_sign_aid(const SignAdapter *sa, SignatureAlgorithmIdentifier_t **sign_alg_id)
{
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(sa->ctx != NULL);
    CHECK_PARAM(sign_alg_id != NULL);

    ret = cryptonite_sign_params_get_sign_aid((CryptoniteSignParams *)sa->ctx, sign_alg_id);

cleanup:

    return ret;
}

static int va_get_sign_aid(const VerifyAdapter *va, SignatureAlgorithmIdentifier_t **sign_alg_id)
{
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(va->ctx != NULL);
    CHECK_PARAM(sign_alg_id != NULL);

    ret = cryptonite_sign_params_get_sign_aid((CryptoniteSignParams *)va->ctx, sign_alg_id);

cleanup:

    return ret;
}

/**
* Очищает контекст sign_adapter_t.
*
* @param sa контекст
*/
static void sa_free(SignAdapter *sa)
{
    LOG_ENTRY();

    if (sa != NULL) {
        sa->sign_data = NULL;
        sa->sign_hash = NULL;
        sa->get_pub_key = NULL;
        sa->has_cert = NULL;
        sa->get_cert = NULL;
        sa->get_digest_alg = NULL;
        sa->get_sign_alg = NULL;
        sa->set_digest_alg = NULL;
        sa->free = NULL;

        cryptonite_sign_params_free((CryptoniteSignParams *)sa->ctx);

        free(sa);
    }
}

void sign_adapter_free(SignAdapter *sa)
{
    if (sa) {
        sa->free(sa);
    }
}

/**
* Очищает контекст verify_adapter_t.
*
* @param va контекст
*/
static void va_free(VerifyAdapter *va)
{
    LOG_ENTRY();

    if (va) {
        cryptonite_sign_params_free((CryptoniteSignParams *)va->ctx);
        free(va);
    }
}

void digest_adapter_free(DigestAdapter *da)
{
    if (da) {
        da->free(da);
    }
}

void verify_adapter_free(VerifyAdapter *va)
{
    if (va) {
        va->free(va);
    }
}

static int validate_priv_pub_key(const CryptoniteSignParams *sign_parameters_str, const ByteArray *priv_key,
        const ByteArray *pub_key)
{
    int ret = RET_OK;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *q = NULL;
    ByteArray *last_bit_ba = NULL;

    CHECK_PARAM(sign_parameters_str);
    CHECK_PARAM(priv_key);

    if (sign_parameters_str->alg_marker == DSTU4145) {
        ret = dstu4145_get_pubkey(sign_parameters_str->alg_type.dstu, priv_key, &qx, &qy);
        if (ret != RET_OK) {
            if (ret == RET_INVALID_PRIVATE_KEY) {
                SET_ERROR(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS);
            } else {
                SET_ERROR(ret);
            }
        }

        if (pub_key != NULL) {
            DO(dstu4145_compress_pubkey(sign_parameters_str->alg_type.dstu, qx, qy, &q));

            if (ba_cmp(q, pub_key) != 0) {
                SET_ERROR(RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV);
            }
        }

        goto cleanup;

    }
    if (sign_parameters_str->alg_marker == ECDSA) {
        ret = ecdsa_get_pubkey(sign_parameters_str->alg_type.ecdsa, priv_key, &qx, &qy);
        if (ret != RET_OK) {
            if (ret == RET_INVALID_PRIVATE_KEY) {
                SET_ERROR(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS);
            } else {
                SET_ERROR(ret);
            }
        }

        if (pub_key != NULL) {
            if (ba_get_buf(pub_key)[0] == 0x04) {
                CHECK_NOT_NULL(q = ba_alloc_by_len(1));
                DO(ba_set(q, 0x04));
                DO(ba_swap(qx));
                DO(ba_swap(qy));
                DO(ba_append(qx, 0, 0, q));
                DO(ba_append(qy, 0, 0, q));
            } else if (ba_get_buf(pub_key)[0] == 0x03 || ba_get_buf(pub_key)[0] == 0x02) {
                int last_bit = 0;
                DO(ecdsa_compress_pubkey(sign_parameters_str->alg_type.ecdsa, qx, qy, &q, &last_bit));
                CHECK_NOT_NULL(last_bit_ba = ba_alloc_by_len(1));
                DO(ba_set(last_bit_ba, last_bit + 2));
                DO(ba_append(last_bit_ba, 0, 0, q));
                //Переводим в бе.
                DO(ba_swap(q));
            }

            if (ba_cmp(q, pub_key) != 0) {
                SET_ERROR(RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV);
            }
        }
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    ba_free(qx);
    ba_free(qy);
    ba_free(q);

    return ret;
}

static __inline int check_signature_alg_params(const OBJECT_IDENTIFIER_t *sign_alg, OidId *id)
{
    OidId sa_aid = 0;
    int ret = RET_OK;

    if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        sa_aid = OID_PKI_DSTU4145_WITH_GOST3411_ID;
    } else if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID))) {
        sa_aid = OID_ECDSA_WITH_SHA1_ID;
    } else if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID))) {
        sa_aid = OID_ECDSA_WITH_SHA224_ID;
    } else if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID))) {
        sa_aid = OID_ECDSA_WITH_SHA256_ID;
    } else if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID))) {
        sa_aid = OID_ECDSA_WITH_SHA384_ID;
    } else if (pkix_check_oid_parent(sign_alg, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID))) {
        sa_aid = OID_ECDSA_WITH_SHA512_ID;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    *id = sa_aid;

cleanup:

    return ret;
}

static __inline int create_digest_aid_by_oid(const OidId id, SignAlgId *s_id, AlgorithmIdentifier_t **aid)
{
    AlgorithmIdentifier_t *digest_aid = NULL;
    SignAlgId sai = 0;
    int ret = RET_OK;

    switch (id) {
    case OID_PKI_DSTU4145_WITH_GOST3411_ID:
        DO(aid_create_gost3411(&digest_aid));
        break;
    case OID_ECDSA_WITH_SHA1_ID:
        ASN_ALLOC(digest_aid);
        DO(aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID)));
        sai = ECDSA;
        break;
    case OID_ECDSA_WITH_SHA224_ID:
        ASN_ALLOC(digest_aid);
        DO(aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID)));
        sai = ECDSA;
        break;
    case OID_ECDSA_WITH_SHA256_ID:
        ASN_ALLOC(digest_aid);
        DO(aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID)));
        sai = ECDSA;
        break;
    case OID_ECDSA_WITH_SHA384_ID:
        ASN_ALLOC(digest_aid);
        DO(aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID)));
        sai = ECDSA;
        break;
    case OID_ECDSA_WITH_SHA512_ID:
        ASN_ALLOC(digest_aid);
        DO(aid_init_by_oid(digest_aid, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID)));
        sai = ECDSA;
        break;
    default:
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

    *aid = digest_aid;
    if (s_id) {
        *s_id = sai;
    }
    digest_aid = NULL;
cleanup:

    aid_free(digest_aid);

    return ret;
}

int sign_adapter_init_by_aid(const ByteArray *priv_key,
        const AlgorithmIdentifier_t *signature_aid,
        const AlgorithmIdentifier_t *alg,
        SignAdapter **sa)
{
    int ret = RET_OK;
    CryptoniteSignParams *sign_parameters_str = NULL;
    SignAdapter *adapter = NULL;
    OidId sa_aid = 0;

    LOG_ENTRY();
    CHECK_PARAM(priv_key != NULL);
    CHECK_PARAM(signature_aid != NULL);
    CHECK_PARAM(alg != NULL);
    CHECK_PARAM(sa != NULL);

    DO(check_signature_alg_params(&signature_aid->algorithm, &sa_aid));

    CALLOC_CHECKED(adapter, sizeof(SignAdapter));
    adapter->sign_data = sa_sign_data;
    adapter->sign_hash = sa_sign_hash;
    adapter->get_pub_key = sa_get_pub_key;
    adapter->has_cert = sa_has_cert;
    adapter->set_cert = sa_set_cert;
    adapter->get_cert = sa_get_cert;
    adapter->set_digest_alg = sa_set_digest_alg;
    adapter->get_digest_alg = sa_get_digest_aid;
    adapter->get_sign_alg = sa_get_sign_aid;
    adapter->free = sa_free;

    CALLOC_CHECKED(sign_parameters_str, sizeof(CryptoniteSignParams));
    DO(create_digest_aid_by_oid(sa_aid, &sign_parameters_str->alg_marker, &sign_parameters_str->digest_aid));

    sign_parameters_str->has_cert = false;
    CHECK_NOT_NULL(sign_parameters_str->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, signature_aid));
    CHECK_NOT_NULL(sign_parameters_str->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, alg));

    DO(cryptonite_sign_params_asn_init(sign_parameters_str));
    DO(cryptonite_sign_params_init(sign_parameters_str));

    DO(validate_priv_pub_key(sign_parameters_str, priv_key, NULL));

    CHECK_NOT_NULL(sign_parameters_str->private_key = ba_copy_with_alloc(priv_key, 0, 0));
    adapter->ctx = sign_parameters_str;
    sign_parameters_str = NULL;
    *sa = adapter;
    adapter = NULL;

cleanup:

    cryptonite_sign_params_free(sign_parameters_str);
    sa_free(adapter);

    return ret;
}

int sign_adapter_init_by_cert(const ByteArray *private_key, const Certificate_t *cert, SignAdapter **sa)
{
    int ret = RET_OK;
    CryptoniteSignParams *sign_parameters_str = NULL;
    SignAdapter *adapter = NULL;
    ByteArray *cert_pub_key = NULL;
    OidId sa_aid = 0;

    LOG_ENTRY();

    CHECK_PARAM(private_key != NULL);
    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(sa != NULL);

    DO(check_signature_alg_params(&cert->tbsCertificate.signature.algorithm, &sa_aid));

    CALLOC_CHECKED(adapter, sizeof(SignAdapter));

    adapter->sign_data = sa_sign_data;
    adapter->sign_hash = sa_sign_hash;
    adapter->get_pub_key = sa_get_pub_key;
    adapter->has_cert = sa_has_cert;
    adapter->set_cert = sa_set_cert;
    adapter->get_cert = sa_get_cert;
    adapter->get_digest_alg = sa_get_digest_aid;
    adapter->get_sign_alg = sa_get_sign_aid;
    adapter->set_digest_alg = sa_set_digest_alg;
    adapter->free = sa_free;

    CALLOC_CHECKED(sign_parameters_str, sizeof(CryptoniteSignParams));

    DO(create_digest_aid_by_oid(sa_aid, &sign_parameters_str->alg_marker, &sign_parameters_str->digest_aid));
    sign_parameters_str->has_cert = true;
    CHECK_NOT_NULL(sign_parameters_str->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.signature));
    CHECK_NOT_NULL(sign_parameters_str->certificate = asn_copy_with_alloc(&Certificate_desc, cert));
    CHECK_NOT_NULL(sign_parameters_str->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.subjectPublicKeyInfo.algorithm));

    DO(cryptonite_sign_params_asn_init(sign_parameters_str));
    DO(cryptonite_sign_params_init(sign_parameters_str));

    DO(spki_get_pub_key(&cert->tbsCertificate.subjectPublicKeyInfo, &cert_pub_key));
    DO(validate_priv_pub_key(sign_parameters_str, private_key, cert_pub_key));

    CHECK_NOT_NULL(sign_parameters_str->private_key = ba_copy_with_alloc(private_key, 0, 0));

    *((void **)&adapter->ctx) = sign_parameters_str;
    sign_parameters_str = NULL;
    *sa = adapter;
    adapter = NULL;

cleanup:

    cryptonite_sign_params_free(sign_parameters_str);
    sa_free(adapter);
    ba_free(cert_pub_key);

    return ret;
}

static int cryptonite_sign_params_set_opt_level(CryptoniteSignParams *ctx, OptLevelId opt_level)
{
    int ret;

    CHECK_PARAM(ctx != NULL);

    if (ctx->alg_marker == DSTU4145) {
        DO(dstu4145_set_opt_level(ctx->alg_type.dstu, opt_level));
    } else if (ctx->alg_marker == ECDSA) {
        DO(ecdsa_set_opt_level(ctx->alg_type.ecdsa, opt_level));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    return ret;
}

int sign_adapter_set_opt_level(SignAdapter *sa, OptLevelId opt_level)
{
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);

    CryptoniteSignParams *ctx = (CryptoniteSignParams *)(sa->ctx);

    DO(cryptonite_sign_params_set_opt_level(ctx, opt_level));

cleanup:

    return ret;
}

int verify_adapter_set_opt_level(VerifyAdapter *va, OptLevelId opt_level)
{
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);

    CryptoniteSignParams *ctx = (CryptoniteSignParams *)(va->ctx);

    DO(cryptonite_sign_params_set_opt_level(ctx, opt_level));

cleanup:

    return ret;
}

static CryptoniteSignParams *cryptonite_sign_params_copy_with_alloc(CryptoniteSignParams *ctx)
{
    CryptoniteSignParams *sign_params = NULL;
    int ret = RET_OK;

    CALLOC_CHECKED(sign_params, sizeof(CryptoniteSignParams));

    if (ctx->public_key) {
        CHECK_NOT_NULL(sign_params->public_key = asn_copy_with_alloc(&BIT_STRING_desc, ctx->public_key));
    }

    if (ctx->asn_dstu_params) {
        CHECK_NOT_NULL(sign_params->asn_dstu_params = asn_copy_with_alloc(&DSTU4145Params_desc, ctx->asn_dstu_params));
    }

    if (ctx->asn_ec_params) {
        CHECK_NOT_NULL(sign_params->asn_ec_params = asn_copy_with_alloc(&ECParameters_desc, ctx->asn_ec_params));
    }

    if (ctx->alg_marker == DSTU4145) {
        CHECK_NOT_NULL(sign_params->alg_type.dstu = dstu4145_copy_with_alloc(ctx->alg_type.dstu));
    } else if (ctx->alg_marker == ECDSA) {
        CHECK_NOT_NULL(sign_params->alg_type.ecdsa = ecdsa_copy_with_alloc(ctx->alg_type.ecdsa));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }
    sign_params->alg_marker = ctx->alg_marker;

    if (ctx->private_key) {
        CHECK_NOT_NULL(sign_params->private_key = ba_copy_with_alloc(ctx->private_key, 0, 0));
    }

    if (ctx->prng_ctx) {
        ByteArray *seed = NULL;
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(prng_next_bytes(ctx->prng_ctx, seed));
        CHECK_NOT_NULL(sign_params->prng_ctx = prng_alloc(PRNG_MODE_DSTU, seed));
        ba_free_private(seed);
    }

    if (ctx->params_aid != NULL) {
        CHECK_NOT_NULL(sign_params->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ctx->params_aid));
    }

    if (ctx->signature_aid != NULL) {
        CHECK_NOT_NULL(sign_params->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ctx->signature_aid));
    }

    if (ctx->digest_aid != NULL) {
        CHECK_NOT_NULL(sign_params->digest_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ctx->digest_aid));
    }

    if (ctx->certificate != NULL) {
        CHECK_NOT_NULL(sign_params->certificate = asn_copy_with_alloc(&Certificate_desc, ctx->certificate));
    }

    sign_params->has_cert = ctx->has_cert;

    if (ctx->digest_sbox != NULL) {
        CHECK_NOT_NULL(sign_params->digest_sbox = ba_copy_with_alloc(ctx->digest_sbox, 0, 0));
    }

cleanup:

    if (ret != RET_OK) {
        cryptonite_sign_params_free(sign_params);
        sign_params = NULL;
    }

    return sign_params;
}

SignAdapter *sign_adapter_copy_with_alloc(const SignAdapter *sa)
{
    SignAdapter *adapter = NULL;
    int ret = RET_OK;

    CHECK_PARAM(sa != NULL);

    CALLOC_CHECKED(adapter, sizeof(SignAdapter));

    adapter->sign_data = sa->sign_data;
    adapter->sign_hash = sa->sign_hash;
    adapter->get_pub_key = sa->get_pub_key;
    adapter->has_cert = sa->has_cert;
    adapter->get_cert = sa->get_cert;
    adapter->set_cert = sa->set_cert;
    adapter->get_digest_alg = sa->get_digest_alg;
    adapter->get_sign_alg = sa->get_sign_alg;
    adapter->set_digest_alg = sa->set_digest_alg;
    adapter->free = sa->free;

    CHECK_NOT_NULL(*((void **)&adapter->ctx) = cryptonite_sign_params_copy_with_alloc((CryptoniteSignParams *)(sa->ctx)));

cleanup:

    if (ret != RET_OK) {
        sign_adapter_free(adapter);
        adapter = NULL;
    }

    return adapter;
}
int verify_adapter_init_by_spki(const AlgorithmIdentifier_t *signature_aid, const SubjectPublicKeyInfo_t *pkey,
        VerifyAdapter **va)
{
    int ret = RET_OK;
    CryptoniteSignParams *sign_parameters_str = NULL;
    VerifyAdapter *adapter = NULL;
    OidId sa_aid = 0;
    LOG_ENTRY();

    CHECK_PARAM(va != NULL);
    CHECK_PARAM(pkey != NULL);
    CHECK_PARAM(signature_aid != NULL);

    CALLOC_CHECKED(adapter, sizeof(VerifyAdapter));

    adapter->verify_data = va_verify_data;
    adapter->verify_hash = va_verify_hash;
    adapter->get_pub_key = va_get_pub_key;
    adapter->has_cert = va_has_cert;
    adapter->get_cert = va_get_cert;
    adapter->set_cert = va_set_cert;
    adapter->get_digest_alg = va_get_digest_aid;
    adapter->get_sign_alg = va_get_sign_aid;
    adapter->set_digest_alg = va_set_digest_alg;
    adapter->free = va_free;

    CALLOC_CHECKED(sign_parameters_str, sizeof(CryptoniteSignParams));

    sign_parameters_str->has_cert = false;
    CHECK_NOT_NULL(sign_parameters_str->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, signature_aid));

    DO(check_signature_alg_params(&signature_aid->algorithm, &sa_aid));
    DO(create_digest_aid_by_oid(sa_aid, NULL, &sign_parameters_str->digest_aid));

    CHECK_NOT_NULL(sign_parameters_str->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &pkey->algorithm));
    CHECK_NOT_NULL(sign_parameters_str->public_key = asn_copy_with_alloc(&BIT_STRING_desc, &pkey->subjectPublicKey));

    DO(cryptonite_sign_params_asn_init(sign_parameters_str));
    DO(cryptonite_sign_params_init(sign_parameters_str));

    *((void **)&adapter->ctx) = sign_parameters_str;
    sign_parameters_str = NULL;
    *va = adapter;
    adapter = NULL;

cleanup:

    cryptonite_sign_params_free(sign_parameters_str);
    va_free(adapter);

    return ret;
}

int verify_adapter_init_by_cert(const Certificate_t *cert, VerifyAdapter **va)
{
    int ret = RET_OK;
    CryptoniteSignParams *sign_parameters_str = NULL;
    VerifyAdapter *adapter = NULL;
    OidId sa_aid = 0;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(va != NULL);

    CALLOC_CHECKED(adapter, sizeof(VerifyAdapter));

    adapter->verify_data = va_verify_data;
    adapter->verify_hash = va_verify_hash;
    adapter->get_pub_key = va_get_pub_key;
    adapter->has_cert = va_has_cert;
    adapter->get_cert = va_get_cert;
    adapter->set_cert = va_set_cert;
    adapter->get_digest_alg = va_get_digest_aid;
    adapter->get_sign_alg = va_get_sign_aid;
    adapter->set_digest_alg = va_set_digest_alg;
    adapter->free = va_free;

    CALLOC_CHECKED(sign_parameters_str, sizeof(CryptoniteSignParams));

    sign_parameters_str->has_cert = true;
    CHECK_NOT_NULL(sign_parameters_str->signature_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.signature));

    DO(check_signature_alg_params(&sign_parameters_str->signature_aid->algorithm, &sa_aid));
    DO(create_digest_aid_by_oid(sa_aid, NULL, &sign_parameters_str->digest_aid));

    CHECK_NOT_NULL(sign_parameters_str->certificate = asn_copy_with_alloc(&Certificate_desc, cert));
    CHECK_NOT_NULL(sign_parameters_str->params_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &cert->tbsCertificate.subjectPublicKeyInfo.algorithm));
    CHECK_NOT_NULL(sign_parameters_str->public_key = asn_copy_with_alloc(&BIT_STRING_desc,
            &cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey));

    DO(cryptonite_sign_params_asn_init(sign_parameters_str));
    DO(cryptonite_sign_params_init(sign_parameters_str));

    *((void **)&adapter->ctx) = sign_parameters_str;
    sign_parameters_str = NULL;
    *va = adapter;
    adapter = NULL;

cleanup:

    cryptonite_sign_params_free(sign_parameters_str);
    va_free(adapter);

    return ret;
}

VerifyAdapter *verify_adapter_copy_with_alloc(const VerifyAdapter *va)
{
    VerifyAdapter *adapter = NULL;
    int ret = RET_OK;

    CHECK_PARAM(va != NULL);

    CALLOC_CHECKED(adapter, sizeof(VerifyAdapter));

    adapter->verify_data = va->verify_data;
    adapter->verify_hash = va->verify_hash;
    adapter->get_pub_key = va->get_pub_key;
    adapter->has_cert = va->has_cert;
    adapter->get_cert = va->get_cert;
    adapter->set_cert = va->set_cert;
    adapter->get_digest_alg = va->get_digest_alg;
    adapter->get_sign_alg = va->get_sign_alg;
    adapter->set_digest_alg = va->set_digest_alg;
    adapter->free = va->free;

    CHECK_NOT_NULL(*((void **)&adapter->ctx) = cryptonite_sign_params_copy_with_alloc((CryptoniteSignParams *)(va->ctx)));

cleanup:

    if (ret != RET_OK) {
        verify_adapter_free(adapter);
        adapter = NULL;
    }

    return adapter;
}

/**
* Преобразовывает 32 битное целое в массив байт. При формировании используется
* правило "младший байт из целого помещается по старшему
* индексу" (big-endian).
*
* @param src    целое
* @param dst    массив байт
* @param dstOff смещение в массиве байт
*/
static void iso15946_int2be(int src, void *dst, int dstOff)
{
    int i;
    uint8_t *ptr = dst;
    for (i = 0; i < 4; i++) {
        ptr[dstOff + i] = (src >> (24 - i * 8));
    }
}

#define KEY_LENGTH 256

/**
* Возвращает SharedInfo.
*
* @param entity_info 64-байтный массив случайных числ
* @param oid идентификатор алгоритма
* @param oid_len размер массива идентификатора алгоритма
* @param shared_info буфер для структуры SharedInfo
* @param shared_info размер буфера для структуры SharedInfo
*/
static void iso15946_shared_info(const ByteArray *entity_info, const void *oid, int oid_len,
        void *shared_info, int shared_info_len)
{
    uint8_t *encode = shared_info;
    uint8_t supp_pub_info_len = 8;
    uint8_t entity_info_len = (uint8_t)ba_get_len(entity_info);
    /*ASN1 head len + ASN1 NULL len = 4. */
    uint8_t alg_id_len = 4 + oid_len;

    if (entity_info != NULL) {

        /* ASN1 DER Explicit. */
        encode[alg_id_len + 2] = 0xa0;
        encode[alg_id_len + 3] = entity_info_len + 2;
        /* ASN1 DER OctetString/ */
        encode[alg_id_len + 4] = 0x04;
        encode[alg_id_len + 5] = entity_info_len;

        ba_to_uint8(entity_info, encode + 6 + alg_id_len, entity_info_len);
    }

    /* ASN1 Sequence. */
    encode[0] = 0x30;
    encode[1] = shared_info_len - 2;

    /* ASN1 Sequence. */
    encode[2] = 0x30;
    encode[3] = alg_id_len - 2;

    /* ASN1 OID. */
    memcpy(encode + 4, oid, oid_len);

    /* ASN1 Null. */
    encode[alg_id_len] = 0x05;
    encode[alg_id_len + 1] = 0x00;

    /* ASN1 DER Explicit. */
    encode[shared_info_len - supp_pub_info_len] = 0xa2;
    encode[shared_info_len - supp_pub_info_len + 1] = 6;
    /* ASN1 DER OctetString KEY_SIZE. */
    encode[shared_info_len - supp_pub_info_len + 2] = 0x04;
    encode[shared_info_len - supp_pub_info_len + 3] = 0x04;
    iso15946_int2be(KEY_LENGTH, shared_info, shared_info_len - supp_pub_info_len + 4);
}

static ByteArray *iso15946_get_not_zero(ByteArray *zx)
{
    size_t len;
    const uint8_t *ptr = ba_get_buf(zx);

    if (ptr == NULL) {
        ERROR_ADD(RET_INVALID_PARAM);
        return NULL;
    }

    len = ba_get_len(zx);
    do {
        if (ptr[len - 1] != 0) {
            return ba_copy_with_alloc(zx, 0, len);
        }
    } while (--len != 0);

    return NULL;
}

static int iso15946_generate_secretc(ByteArray *zx, const ByteArray *entity_info, const void *oid,
        int oid_len, ByteArray **secret)
{
    int ret = RET_OK;
    int shared_info_len;
    uint8_t *shared_info = NULL;
    Gost34311Ctx *ctx = NULL;
    ByteArray *sync = NULL;
    ByteArray *hash_data = NULL;
    unsigned char COUNTER[4] = {0, 0, 0, 1};

    CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
    ba_set(sync, 0);
    shared_info_len = 14 + oid_len;

    if (entity_info != NULL) {
        shared_info_len += 68;
    }

    MALLOC_CHECKED(shared_info, shared_info_len * sizeof(uint8_t));
    iso15946_shared_info(entity_info, oid, oid_len, shared_info, shared_info_len);

    CHECK_NOT_NULL(ctx = gost34_311_alloc(GOST28147_SBOX_ID_1, sync));
    CHECK_NOT_NULL(hash_data = iso15946_get_not_zero(zx));
    DO(ba_swap(hash_data));
    DO(gost34_311_update(ctx, hash_data));
    ba_free(hash_data);

    /* Про затвердження Технічних специфікацій форматів криптографічних повідомлень. Захищені дані
     *
     * 5.6.3. KDF-функція у циклічній групі поля
     *   ...
     *   5) Алгоритм формування ключа КШК:
     *     ...
     *     б)  якщо довжина КМ дорівнює довжині КШК, то за КШК приймають КМ;
     */
    CHECK_NOT_NULL(hash_data = ba_alloc_from_uint8(COUNTER, sizeof(COUNTER)));
    DO(gost34_311_update(ctx, hash_data));
    ba_free(hash_data);
    CHECK_NOT_NULL(hash_data = ba_alloc_from_uint8(shared_info, shared_info_len));
    DO(gost34_311_update(ctx, hash_data));

    DO(gost34_311_final(ctx, secret));

cleanup:

    ba_free(sync);
    gost34_311_free(ctx);
    free(shared_info);
    ba_free(hash_data);

    return ret;
}

/** Размерности. */
#define MAC_SIZE      4
#define IV_SIZE       8
#define KEY_SIZE      32
#define WRAP_KEY_SIZE 44

/** Вектор инициализации для последнего этапа шифрования и первого этапа расшифрования ключа. */
static const unsigned char IV_WRAP[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };

/**
* Шифрует ключ шифрования по алгоритму GOST28147Wrap.
* Взято из "Наказ Адмiнiстрацiї Державної 14 січня 2013 р. за № 108/22640" VI.1.
*
* @param params     параметры криптосистемы, в соответствии с ГОСТ 28147
* @param kek        32-байтный ключ шифрования ключа
* @param key        32-байтный шифруемый ключ
* @param prng       контекст генератора псевдослучайных чисел
* @param wraped_key 44-байтный буфер для зашифрованного ключа
*
* @return код ошибки
*/
int gost28147_wrap_key(ByteArray *sbox, const ByteArray *kek, const ByteArray *key, PrngCtx *prng,
        ByteArray **wraped_key)
{
    ByteArray *out = NULL;
    ByteArray *mac = NULL;
    ByteArray *iv = NULL;
    ByteArray *w_key = NULL;
    ByteArray *biv_wrap = NULL;
    int ret = RET_OK;
    Gost28147Ctx *params = NULL;

    CHECK_PARAM(sbox);
    CHECK_PARAM(kek);
    CHECK_PARAM(key);
    CHECK_PARAM(prng);
    CHECK_PARAM(wraped_key);

    CHECK_NOT_NULL(biv_wrap = ba_alloc_from_uint8(IV_WRAP, sizeof(IV_WRAP)));
    CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(sbox));
    CHECK_NOT_NULL(w_key = ba_alloc());
    DO(gost28147_init_mac(params, kek));
    DO(gost28147_update_mac(params, key));
    DO(gost28147_final_mac(params, &mac));

    /* Установка ГПСЧ. */
    CHECK_NOT_NULL(iv = ba_alloc_by_len(IV_SIZE));
    rs_std_next_bytes(iv);
    DO(prng_next_bytes(prng, iv));

    DO(gost28147_init_cfb(params, kek, iv));
    ba_append(iv, 0, 0, w_key);

    DO(gost28147_encrypt(params, key, &out));
    ba_append(out, 0, 0, w_key);
    ba_free(out);
    out = NULL;

    DO(gost28147_encrypt(params, mac, &out));
    ba_append(out, 0, 0, w_key);

    DO(ba_swap(w_key));

    DO(gost28147_init_cfb(params, kek, biv_wrap));
    DO(gost28147_encrypt(params, w_key, wraped_key));

cleanup:

    ba_free(out);
    ba_free(biv_wrap);
    ba_free(mac);
    ba_free(iv);
    ba_free_private(w_key);

    gost28147_free(params);

    return ret;
}

/**
* Расшифровывает ключ по алгоритму GOST28147Wrap.
* Взято из "Наказ Адмiнiстрацiї Державної 14 січня 2013 р. за № 108/22640" VI.1.
*
* @param params     параметры криптосистемы, в соответствии с ГОСТ 28147
* @param kek        32-байтный ключ шифрования ключа
* @param wraped_key 44-байтный зашифрованный ключ
* @param key        32-байтный буфер для расшифрованного ключа
*
* @return код ошибки
*/
int gost28147_unwrap_key(const ByteArray *sbox, const ByteArray *kek, const ByteArray *wraped_key, ByteArray **key)
{
    int ret = RET_OK;
    ByteArray *key_unwrap = NULL;
    ByteArray *mac = NULL;
    ByteArray *actual_mac = NULL;
    ByteArray *dec_wraped_key = NULL;
    ByteArray *wrap_iv = NULL;
    ByteArray *iv = NULL;
    ByteArray *enc_key = NULL;
    ByteArray *enc_mac = NULL;

    Gost28147Ctx *params = NULL;

    CHECK_PARAM(sbox);
    CHECK_PARAM(kek);
    CHECK_PARAM(wraped_key);
    CHECK_PARAM(key);

    CHECK_NOT_NULL(params = gost28147_alloc_user_sbox(sbox));
    CHECK_NOT_NULL(wrap_iv = ba_alloc_from_uint8(IV_WRAP, sizeof(IV_WRAP)));

    DO(gost28147_init_cfb(params, kek, wrap_iv));
    DO(gost28147_decrypt(params, wraped_key, &dec_wraped_key));
    DO(ba_swap(dec_wraped_key));

    CHECK_NOT_NULL(iv = ba_copy_with_alloc(dec_wraped_key, 0, IV_SIZE));

    DO(gost28147_init_cfb(params, kek, iv));
    CHECK_NOT_NULL(enc_key = ba_copy_with_alloc(dec_wraped_key, IV_SIZE, KEY_SIZE));
    DO(gost28147_decrypt(params, enc_key, &key_unwrap));

    CHECK_NOT_NULL(enc_mac = ba_copy_with_alloc(dec_wraped_key, IV_SIZE + KEY_SIZE, MAC_SIZE));
    DO(gost28147_decrypt(params, enc_mac, &mac));

    DO(gost28147_init_mac(params, kek));
    DO(gost28147_update_mac(params, key_unwrap));
    DO(gost28147_final_mac(params, &actual_mac));

    if (ba_cmp(actual_mac, mac)) {
        SET_ERROR(RET_PKIX_INVALID_MAC);
    }

    *key = key_unwrap;
    key_unwrap = NULL;

cleanup:

    gost28147_free(params);
    ba_free_private(key_unwrap);
    ba_free(mac);
    ba_free(actual_mac);
    ba_free(dec_wraped_key);
    ba_free(iv);
    ba_free(wrap_iv);
    ba_free(enc_key);
    ba_free(enc_mac);

    return ret;
}

int wrap_session_key(const DhAdapter *dha, const ByteArray *pub_key, const ByteArray *session_key,
        const ByteArray *rnd_bytes, ByteArray **wrapped_key)
{
    int ret = RET_OK;

    AlgorithmIdentifier_t *aid = NULL;
    PrngCtx *prng_source = NULL;
    ByteArray *zx = NULL;
    ByteArray *zy = NULL;
    ByteArray *sbox = NULL;
    ByteArray *kek = NULL;
    ByteArray *seed = NULL;

    LOG_ENTRY();

    CHECK_PARAM(dha != NULL);
    CHECK_PARAM(session_key != NULL);
    CHECK_PARAM(rnd_bytes != NULL);
    CHECK_PARAM(wrapped_key != NULL);

    DO(dha->get_alg(dha, &aid));
    DO(dha->dh(dha, pub_key, &zx, &zy));

    DO(iso15946_generate_secretc(zx, rnd_bytes, CFB_WRAP_OID, sizeof(CFB_WRAP_OID), &kek));

    DO(get_sbox_from_aid(aid, &sbox));

    CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
    DO(rs_std_next_bytes(seed));
    CHECK_NOT_NULL(prng_source = prng_alloc(PRNG_MODE_DEFAULT, seed));

    DO(gost28147_wrap_key(sbox, kek, session_key, prng_source, wrapped_key));

cleanup:

    aid_free(aid);
    prng_free(prng_source);
    ba_free(zx);
    ba_free(zy);
    ba_free(sbox);
    ba_free(kek);
    ba_free(seed);

    return ret;
}

int unwrap_session_key(const DhAdapter *dha, const ByteArray *wrapped_key, const ByteArray *rnd_bytes,
        const ByteArray *issuer_pub_key, ByteArray **session_key)
{
    int ret = RET_OK;

    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *sbox = NULL;
    ByteArray *kek = NULL;
    ByteArray *zx = NULL;
    ByteArray *zy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(dha != NULL);
    CHECK_PARAM(wrapped_key != NULL);
    if (rnd_bytes != NULL) {
        CHECK_PARAM(ba_get_len(rnd_bytes) == 64);
    }
    CHECK_PARAM(issuer_pub_key != NULL);
    CHECK_PARAM(session_key != NULL);

    DO(dha->get_alg(dha, &aid));
    DO(dha->dh(dha, issuer_pub_key, &zx, &zy));

    DO(iso15946_generate_secretc(zx, rnd_bytes, CFB_WRAP_OID, sizeof(CFB_WRAP_OID), &kek));
    DO(get_sbox_from_aid(aid, &sbox));
    DO(gost28147_unwrap_key(sbox, kek, wrapped_key, session_key));

cleanup:

    ba_free(sbox);
    ba_free(kek);
    ba_free(zx);
    ba_free(zy);

    aid_free(aid);

    return ret;
}

/**
 * 128 -> 64
 */
static int compress_sbox_core(ByteArray *sbox, unsigned char *compress_sbox)
{
    int ret = RET_OK;
    int i, j;
    unsigned char *s = NULL;
    size_t s_len = 0;

    LOG_ENTRY();

    CHECK_PARAM(compress_sbox != NULL);
    CHECK_PARAM(sbox != NULL);

    DO(ba_to_uint8_with_alloc(sbox, &s, &s_len));
    if (s_len != 128) {
        LOG_ERROR();
        SET_ERROR(RET_INVALID_PARAM);
    }

    memset(compress_sbox, 0, 64);

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++) {
            compress_sbox[(i << 3) + (j >> 1)] |= ((s[16 * i + j] << ((~j & 1) << 2)));
        }
    }

    free(s);
cleanup:
    return ret;
}

int create_dstu4145_spki(const OBJECT_IDENTIFIER_t *signature_alg_oid,
        const Dstu4145Ctx *ec_params,
        const Gost28147Ctx *cipher_params,
        const ByteArray *pub_key,
        SubjectPublicKeyInfo_t **dstu_spki)
{
    int ret = RET_OK;

    BIT_STRING_t *pub_key_bs = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    AlgorithmIdentifier_t *algorithm = NULL;

    LOG_ENTRY();

    CHECK_PARAM(signature_alg_oid != NULL);
    CHECK_PARAM(ec_params != NULL);
    CHECK_PARAM(pub_key != NULL);
    CHECK_PARAM(dstu_spki != NULL);

    if (!pkix_check_oid_parent(signature_alg_oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    DO(aid_create_dstu4145(ec_params, cipher_params, is_dstu_le_params(signature_alg_oid), &algorithm));
    DO(convert_pubkey_bytes_to_bitstring(signature_alg_oid, pub_key, &pub_key_bs));
    ASN_ALLOC(spki);
    DO(asn_copy(&AlgorithmIdentifier_desc, algorithm, &spki->algorithm));
    DO(asn_copy(&BIT_STRING_desc, pub_key_bs, &spki->subjectPublicKey));

    *dstu_spki = spki;
    spki = NULL;

cleanup:

    ASN_FREE(&BIT_STRING_desc, pub_key_bs);
    ASN_FREE(&AlgorithmIdentifier_desc, algorithm);
    ASN_FREE(&SubjectPublicKeyInfo_desc, spki);

    return ret;
}

int create_ecdsa_spki(const OBJECT_IDENTIFIER_t *signature_alg_oid,
        const ANY_t *pub_key_params,
        const EcdsaCtx *ec_params,
        const ByteArray *pub_key,
        SubjectPublicKeyInfo_t **ecdsa_spki)
{
    int ret = RET_OK;

    BIT_STRING_t *pub_key_bs = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    AlgorithmIdentifier_t *algorithm = NULL;
    EcdsaParamsId param = 0;
    OBJECT_IDENTIFIER_t *pub_key_alg = NULL;

    LOG_ENTRY();

    CHECK_PARAM(signature_alg_oid != NULL);
    CHECK_PARAM(pub_key_params != NULL);
    CHECK_PARAM(ec_params != NULL);
    CHECK_PARAM(pub_key != NULL);
    CHECK_PARAM(ecdsa_spki != NULL);

    if (!pkix_check_oid_parent(signature_alg_oid, oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    DO(ANY_to_type(pub_key_params, &OBJECT_IDENTIFIER_desc, (void **)&pub_key_alg));
    if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_192_R1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P192_R1;
    } else if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_224_R1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P224_R1;
    } else if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_256_R1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P256_R1;
    } else if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_384_R1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P384_R1;
    } else if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_521_R1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P521_R1;
    } else if (pkix_check_oid_equal(pub_key_alg, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_256_K1_ID))) {
        param = ECDSA_PARAMS_ID_SEC_P256_K1;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    DO(aid_create_ecdsa_pubkey(param, &algorithm));
    DO(convert_pubkey_bytes_to_bitstring(signature_alg_oid, pub_key, &pub_key_bs));
    ASN_ALLOC(spki);
    DO(asn_copy(&AlgorithmIdentifier_desc, algorithm, &spki->algorithm));
    DO(asn_copy(&BIT_STRING_desc, pub_key_bs, &spki->subjectPublicKey));

    *ecdsa_spki = spki;
    spki = NULL;

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, pub_key_alg);
    ASN_FREE(&BIT_STRING_desc, pub_key_bs);
    ASN_FREE(&AlgorithmIdentifier_desc, algorithm);
    ASN_FREE(&SubjectPublicKeyInfo_desc, spki);

    return ret;
}

int get_gost28147_cipher_params(const AlgorithmIdentifier_t *aid, OCTET_STRING_t **dke)
{
    int ret = RET_OK;
    ByteArray *sbox = NULL;
    uint8_t compress_sbox[64];

    DSTU4145Params_t *d_params = NULL;

    LOG_ENTRY();

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(dke != NULL);

    if (pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        CHECK_NOT_NULL(d_params = asn_any2type(aid->parameters, &DSTU4145Params_desc));

        if (d_params->dke != NULL) {
            CHECK_NOT_NULL(*dke = asn_copy_with_alloc(&OCTET_STRING_desc, d_params->dke));
        } else {
            DO(get_sbox_by_id(GOST28147_SBOX_ID_1, &sbox));
            DO(compress_sbox_core(sbox, compress_sbox));
            DO(asn_create_octstring(compress_sbox, 64, dke));
        }

    } else if (pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {

        /*
         * Инициализация параметров ГОСТ 28147 для хеширования. Алгоритм
         * хэширования ГОСТ 34.311-95: поле “algorithm” должно иметь значение:
         * Gost34311 OBJECT IDENTIFIER ::= {iso(1) member-body(2)
         * Ukraine(804) root(2) security(1) cryptography(1) ua-pki(1) alg(1)
         * hash(2) 1} Поле “parameters” должно отсутствовать.
         */

        if (aid->parameters == NULL) {
            DO(get_sbox_by_id(GOST28147_SBOX_ID_1, &sbox));
            DO(compress_sbox_core(sbox, compress_sbox));
            DO(asn_create_octstring(compress_sbox, 64, dke));
        } else {
            SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
        }

    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

cleanup:

    ba_free(sbox);
    ASN_FREE(&DSTU4145Params_desc, d_params);

    return ret;
}

int get_gost28147_aid(PrngCtx *prng, const OBJECT_IDENTIFIER_t *oid, const Certificate_t *cert_with_dke,
        AlgorithmIdentifier_t **aid_gost)
{
    int ret = RET_OK;

    ByteArray *bytes = NULL;
    GOST28147Params_t *params = NULL;
    const AlgorithmIdentifier_t *signature_aid = NULL;
    OCTET_STRING_t *dke = NULL;
    OCTET_STRING_t *iv = NULL;
    AlgorithmIdentifier_t *aid = NULL;

    LOG_ENTRY();

    CHECK_PARAM(prng != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(cert_with_dke != NULL);
    CHECK_PARAM(aid_gost != NULL);

    CHECK_NOT_NULL(bytes = ba_alloc_by_len(8));
    DO(prng_next_bytes(prng, bytes));
    DO(asn_create_octstring_from_ba(bytes, &iv));

    signature_aid = &cert_with_dke->tbsCertificate.subjectPublicKeyInfo.algorithm;
    DO(get_gost28147_cipher_params(signature_aid, &dke));

    ASN_ALLOC(params);
    DO(asn_copy(&OCTET_STRING_desc, iv, &params->iv));
    DO(asn_copy(&OCTET_STRING_desc, dke, &params->dke));

    CHECK_NOT_NULL(aid = aid_alloc());
    DO(aid_init(aid, oid, &GOST28147Params_desc, params));

    *aid_gost = aid;
    aid = NULL;

cleanup:

    ba_free(bytes);
    ASN_FREE(&OCTET_STRING_desc, iv);
    ASN_FREE(&OCTET_STRING_desc, dke);
    ASN_FREE(&GOST28147Params_desc, params);
    ASN_FREE(&AlgorithmIdentifier_desc, aid);

    return ret;
}

/**
 * Возвращает текущий идентификатор алгоритма.
 *
 * @param dha контекст адаптера
 * @param alg буфер для идентификатора алгоритма
 *
 * @return код ошибки
 */
static int dha_get_alg(const DhAdapter *dha, AlgorithmIdentifier_t **alg)
{
    int ret = RET_OK;
    CryptoniteDhParams *params;

    LOG_ENTRY();

    CHECK_PARAM(dha != NULL);
    CHECK_PARAM(alg != NULL);

    params = (CryptoniteDhParams *)dha->ctx;

    if (!params->dh_aid) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CONTEXT_NOT_READY);
    }

    CHECK_NOT_NULL(*alg = asn_copy_with_alloc(&SignatureAlgorithmIdentifier_desc, params->dh_aid));

cleanup:

    return ret;
}

/**
 * Возвращает открытый ключ.
 *
 * @param dha контекст адаптера
 * @param pub_key открытый ключ
 *
 * @return код ошибки
 */
static int dha_get_pub_key(const DhAdapter *dha, ByteArray **pub_key)
{
    int ret = RET_OK;
    CryptoniteDhParams *params;
    Dstu4145Ctx *dstu_params = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(dha != NULL);
    CHECK_PARAM(pub_key != NULL);

    params = (CryptoniteDhParams *)dha->ctx;

    DO(aid_get_dstu4145_params(params->dh_aid, &dstu_params));
    DO(dstu4145_get_pubkey(dstu_params, params->key, &qx, &qy));
    DO(dstu4145_compress_pubkey(dstu_params, qx, qy, pub_key));

cleanup:

    dstu4145_free(dstu_params);
    ba_free(qx);
    ba_free(qy);

    return ret;
}

static int dha_dh(const DhAdapter *dha, const ByteArray *pub_key, ByteArray **zx, ByteArray **zy)
{
    int ret = RET_OK;
    CryptoniteDhParams *params;
    Dstu4145Ctx *dstu_params = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(dha != NULL);
    CHECK_PARAM(pub_key != NULL);
    CHECK_PARAM(zx != NULL);
    CHECK_PARAM(zy != NULL);

    params = (CryptoniteDhParams *)dha->ctx;

    DO(aid_get_dstu4145_params(params->dh_aid, &dstu_params));
    DO(dstu4145_decompress_pubkey(dstu_params, pub_key, &qx, &qy));

    DO(dstu4145_dh(dstu_params, true, params->key, qx, qy, zx, zy));

cleanup:

    dstu4145_free(dstu_params);
    ba_free(qx);
    ba_free(qy);

    return ret;
}

/**
* Очищает контекст dh_adapter_t.
*
* @param va контекст
*/
static void dha_free(DhAdapter *dha)
{
    LOG_ENTRY();

    if (dha) {
        CryptoniteDhParams *params = (CryptoniteDhParams *)dha->ctx;

        if (params) {
            aid_free(params->dh_aid);
            ba_free_private(params->key);
            free(params);
        }

        free(dha);
    }
}

/**
 * Инициализирует dh adapter.
 *
 * @param priv_key закрытый ключ
 * @pub_key        открытый ключ
 * @param aid      ASN1-структура алгоритма подписи
 * @param dha      буфер для dh адаптера
 *
 * @return код ошибки
 */
int dh_adapter_init(const ByteArray *priv_key, const AlgorithmIdentifier_t *aid, DhAdapter **dha)
{
    int ret = RET_OK;
    CryptoniteDhParams *dh_params_str;
    DhAdapter *adapter = NULL;

    LOG_ENTRY();

    CHECK_PARAM(priv_key != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(dha != NULL);

    CALLOC_CHECKED(adapter, sizeof(DhAdapter));

    adapter->dh = dha_dh;
    adapter->get_alg = dha_get_alg;
    adapter->get_pub_key = dha_get_pub_key;
    adapter->free = dha_free;

    CALLOC_CHECKED(dh_params_str, sizeof(CryptoniteDhParams));
    CHECK_NOT_NULL(dh_params_str->dh_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, aid));
    CHECK_NOT_NULL(dh_params_str->key = ba_copy_with_alloc(priv_key, 0, 0));

    *((void **)&adapter->ctx) = dh_params_str;
    *dha = adapter;
cleanup:

    if (ret != RET_OK) {
        dha_free(adapter);
    }

    return ret;
}

DhAdapter *dh_adapter_copy_with_alloc(const DhAdapter *dha)
{
    DhAdapter *adapter = NULL;
    CryptoniteDhParams *ctx;
    CryptoniteDhParams *ctx_copy = NULL;
    int ret = RET_OK;

    CHECK_PARAM(dha != NULL);

    CALLOC_CHECKED(adapter, sizeof(DhAdapter));

    adapter->dh = dha->dh;
    adapter->get_alg = dha->get_alg;
    adapter->get_pub_key = dha->get_pub_key;
    adapter->free = dha->free;

    ctx = (CryptoniteDhParams *)(dha->ctx);
    CALLOC_CHECKED(ctx_copy, sizeof(CryptoniteDhParams));
    CHECK_NOT_NULL(ctx_copy->dh_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, ctx->dh_aid));
    CHECK_NOT_NULL(ctx_copy->key = ba_copy_with_alloc(ctx->key, 0, 0));

    *((void **)&adapter->ctx) = ctx_copy;

cleanup:

    if (ret != RET_OK) {
        dh_adapter_free(adapter);
        adapter = NULL;
    }

    return adapter;
}

/**
* Очищает контекст dh adapter.
*
* @param dha контекст
*/
void dh_adapter_free(DhAdapter *dha)
{
    if (dha) {
        dha->free(dha);
    }
}
