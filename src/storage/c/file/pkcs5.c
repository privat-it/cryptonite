/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkcs5.h"

#include "pkix_macros_internal.h"
#include "storage_errors.h"
#include "cryptonite_manager.h"
#include "PBES2-params.h"
#include "hmac.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "aid.h"
#include "kdf.h"


#undef FILE_MARKER
#define FILE_MARKER "storage/pkcs5.c"


static int pbes2_decrypt(const AlgorithmIdentifier_t *aid,
        const ByteArray *dk,
        const ByteArray *data,
        ByteArray **decrypt)
{
    int ret = RET_OK;

    CipherAdapter *ca = NULL;

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(dk != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(decrypt != NULL);

    DO(cipher_adapter_init(aid, &ca));
    DO(ca->decrypt(ca, dk, data, decrypt));

cleanup:

    cipher_adapter_free(ca);

    return ret;
}

static int pbes2_encrypt(const AlgorithmIdentifier_t *aid,
        const ByteArray *dk,
        const ByteArray *data,
        ByteArray **encrypt)
{
    int ret = RET_OK;

    CipherAdapter *ca = NULL;

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(dk != NULL);
    CHECK_PARAM(data != NULL);
    CHECK_PARAM(encrypt != NULL);

    DO(cipher_adapter_init(aid, &ca));
    DO(ca->encrypt(ca, dk, data, encrypt));

cleanup:

    cipher_adapter_free(ca);

    return ret;
}

int pkcs5_decrypt_dstu(const EncryptedPrivateKeyInfo_t *container,
        const char *pass,
        ByteArray **key)
{
    int ret = RET_OK;

    ByteArray *dk = NULL;
    ByteArray *encrypted = NULL;
    PBES2_params_t *params = NULL;
    const PBES2_KDFs_t *kdf_params;
    ByteArray *salt = NULL;
    size_t key_len = 0;
    unsigned long iterations;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(key != NULL);

    if (!pkix_check_oid_equal(&container->encryptionAlgorithm.algorithm, oids_get_oid_numbers_by_id(OID_PBES2_ID))) {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_ENC_PRIV_KEY_ALG);
    }

    CHECK_NOT_NULL(params = asn_any2type(container->encryptionAlgorithm.parameters, &PBES2_params_desc));

    if (!pkix_check_oid_equal(&params->keyDerivationFunc.algorithm, oids_get_oid_numbers_by_id(OID_KDF_ID))) {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
    }

    kdf_params = &params->keyDerivationFunc;

    DO(asn_OCTSTRING2ba(&kdf_params->parameters.salt.choice.specified, &salt));
    DO(asn_INTEGER2ulong(&kdf_params->parameters.iterationCount, &iterations));

    if (pkix_check_oid_parent(&params->encryptionScheme.algorithm, oids_get_oid_numbers_by_id(OID_GOST28147_DSTU_ID))) {
        key_len = 32;
    } else if (pkix_check_oid_parent(&params->encryptionScheme.algorithm, oids_get_oid_numbers_by_id(OID_AES256_CBC_ID))) {
        key_len = 32;
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_ENC_SCHEME_ALG);
    }

    if (pkix_check_oid_equal(&kdf_params->parameters.prf->algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_HMAC_GOST3411_ID))) {
        DO(kdf_pbkdf2(pass, salt, iterations, key_len, PBKDF2_GOST_HMAC_ID, &dk));
    } else if (pkix_check_oid_equal(&kdf_params->parameters.prf->algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_HMAC_SHA1_ID))) {
        DO(kdf_pbkdf2(pass, salt, iterations, key_len, PBKDF2_SHA1_HMAC_ID, &dk));
    } else if (kdf_params->parameters.prf == NULL) { //DEFAULT SHA1
        DO(kdf_pbkdf2(pass, salt, iterations, key_len, PBKDF2_SHA1_HMAC_ID, &dk));
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_KDF_PARAMS_ALG);
    }

    DO(asn_OCTSTRING2ba(&container->encryptedData, &encrypted));
    DO(pbes2_decrypt(&params->encryptionScheme, dk, encrypted, key));

cleanup:

    ba_free(dk);
    ba_free(encrypted);
    ba_free(salt);

    ASN_FREE(&PBES2_params_desc, params);

    return ret;
}

int pkcs5_encrypt_dstu(const ByteArray *key,
        const char *pass,
        const ByteArray *salt,
        unsigned long iterations,
        const AlgorithmIdentifier_t *encrypt_aid,
        EncryptedPrivateKeyInfo_t **container)
{
    int ret = RET_OK;

    ByteArray *dk = NULL;
    ByteArray *encrypted = NULL;
    ByteArray *data = NULL;

    PBES2_params_t *params = NULL;
    PBES2_KDFs_t *kdf_params = NULL;
    EncryptedPrivateKeyInfo_t *ecrypt_key = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    size_t key_len = 0;
    Pbkdf2HmacId hmac_id;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(encrypt_aid != NULL);
    CHECK_PARAM(container != NULL);

    ASN_ALLOC(kdf_params);
    DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers, oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers_len,
            &kdf_params->algorithm));
    DO(asn_ulong2INTEGER(&kdf_params->parameters.iterationCount, iterations));
    kdf_params->parameters.salt.present = PBKDF2_Salt_PR_specified;
    DO(asn_ba2OCTSTRING(salt, &kdf_params->parameters.salt.choice.specified));

    //TODO: остальные алгоритмы
    if (pkix_check_oid_parent(&encrypt_aid->algorithm, oids_get_oid_numbers_by_id(OID_GOST28147_DSTU_ID))) {
        key_len = 32;
        DO(aid_create_hmac_gost3411(&aid));
        hmac_id = PBKDF2_GOST_HMAC_ID;
    } else if (pkix_check_oid_equal(&encrypt_aid->algorithm, oids_get_oid_numbers_by_id(OID_AES256_CBC_ID))) {
        key_len = 32;
        //Default sha1
        hmac_id = PBKDF2_SHA1_HMAC_ID;
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_ENC_ALG);
    }

    if (aid != NULL) {
        CHECK_NOT_NULL(kdf_params->parameters.prf = asn_copy_with_alloc(&AlgorithmIdentifier_desc, aid));
    }

    ASN_ALLOC(params);
    DO(asn_copy(&PBES2_KDFs_desc, kdf_params, &params->keyDerivationFunc));
    DO(asn_copy(&AlgorithmIdentifier_desc, encrypt_aid, &params->encryptionScheme));

    ASN_ALLOC(ecrypt_key);
    DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers, oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers_len,
            &ecrypt_key->encryptionAlgorithm.algorithm));
    DO(asn_create_any(&PBES2_params_desc, params, &ecrypt_key->encryptionAlgorithm.parameters));

    DO(kdf_pbkdf2(pass, salt, iterations, key_len, hmac_id, &dk));

    DO(pbes2_encrypt(&params->encryptionScheme, dk, key, &encrypted));
    DO(asn_ba2OCTSTRING(encrypted, &ecrypt_key->encryptedData));

    *container = ecrypt_key;
    ecrypt_key = NULL;

cleanup:

    ba_free(dk);
    ba_free(encrypted);
    ba_free(data);

    aid_free(aid);

    ASN_FREE(&PBES2_KDFs_desc, kdf_params);
    ASN_FREE(&PBES2_params_desc, params);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, ecrypt_key);

    return ret;
}

int pkcs5_get_type(const EncryptedPrivateKeyInfo_t *key, Pkcs5Type *type)
{
    int ret = RET_OK;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(type != NULL);

    if (asn_check_oid_equal(&key->encryptionAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers, oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers_len)) {
        *type = PKCS5_DSTU;
    } else {
        *type = PKCS5_UNKNOWN;
    }

cleanup:

    return ret;
}
