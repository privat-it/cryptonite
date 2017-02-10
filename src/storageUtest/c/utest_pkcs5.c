/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "../../storage/c/file/pkcs5.h"
#include "test_utils.h"
#include "storage_errors.h"
#include "PBES2-params.h"
#include "aid.h"

static void test_pkcs5_get_type(void)
{
    ByteArray *encrypted_key = ba_alloc_from_le_hex_string("308201AA3081B006092A864886F70D01050D3081A2304306092A864886F70D01050C30360420A75E8C61FC464EFAB889E6649432B008EE4E19150A83AA6F100F78FA2D7E5BC302022710300E060A2A8624020101010101020500305B060B2A86240201010101010103304C0408C72C952E189D42BD0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040481F43BF7164B530944870E1886E7B849CB18C6552D827D069BF67C986AA6F8308CAD701008A8FE00FA99EB4A3E36F00130C0A8F035AC47BC6A0D8946F423ECE5AF209DE31191F96922C5905E8BA6C71DB6091BD98E797C8B622041E9E9C6DF0FA1418891742E6EB7C39029A4179D6F90E9A9FAFA2877728B981A60E2758742ECE5D56E5BFE12A445E30C1926171714B1EC07D28A02BC924B8FB617F08A41461AFAAAEE88EFFA8F1ACD14C7C090AD27BECD140E34E0615200E41449422E7BFB8243B6C8DDFDBCF7151FF062C9BAAF4BFA95A072CEDE2D83EB01D2D37BE0CC2D0BF9B801D4FDBE51452DF5F3356F163B27CCE527E0858C");
    EncryptedPrivateKeyInfo_t *key = NULL;
    Pkcs5Type type;

    ASSERT_NOT_NULL(key = asn_decode_ba_with_alloc(&EncryptedPrivateKeyInfo_desc, encrypted_key));
    ASSERT_RET_OK(pkcs5_get_type(key, &type));
    ASSERT_TRUE(type == PKCS5_DSTU);

cleanup:

    ba_free(encrypted_key);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, key);

}

static void test_pkcs5_get_type_2(void)
{
    OBJECT_IDENTIFIER_t *algorithm = NULL;
    EncryptedPrivateKeyInfo_t *key = NULL;
    Pkcs5Type type;
    int ret = RET_OK;

    ASN_ALLOC(key);
    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &algorithm));
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, algorithm, &key->encryptionAlgorithm.algorithm));

    ASSERT_RET_OK(pkcs5_get_type(key, &type));
    ASSERT_TRUE(type == PKCS5_UNKNOWN);

cleanup:

    ASN_FREE(&EncryptedPrivateKeyInfo_desc, key);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, algorithm);
}

static void test_pkcs5_decrypt_dstu_unsup_enc_priv_key_alg(void)
{
    OBJECT_IDENTIFIER_t *algorithm = NULL;
    EncryptedPrivateKeyInfo_t *encr_key = NULL;
    const char *pass = "123456";
    ByteArray *key = NULL;
    int ret = RET_OK;

    ASN_ALLOC(encr_key);
    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &algorithm));
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, algorithm, &encr_key->encryptionAlgorithm.algorithm));

    ASSERT_RET(RET_STORAGE_UNSUPPORTED_ENC_PRIV_KEY_ALG, pkcs5_decrypt_dstu(encr_key, pass, &key));
    ASSERT_TRUE(key == NULL);

cleanup:

    ba_free(key);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encr_key);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, algorithm);
}

static void test_pkcs5_decrypt_dstu_unsup_enc_scheme_alg(void)
{
    EncryptedPrivateKeyInfo_t *encr_key = NULL;
    const char *pass = "123456";
    ByteArray *key = NULL;
    unsigned long iterations = 10000;
    ByteArray *salt = ba_alloc_from_le_hex_string("1680D35D1040C58443A2615A841FC813A541D53FB38614536A5BFBD40C6ACE67");
    PBES2_params_t *params = NULL;
    PBES2_KDFs_t *kdf_params = NULL;
    AlgorithmIdentifier_t *encr_aid = aid_alloc();
    int ret = RET_OK;

    ASN_ALLOC(kdf_params);
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers, oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers_len,
            &kdf_params->algorithm));
    ASSERT_RET_OK(asn_ulong2INTEGER(&kdf_params->parameters.iterationCount, iterations));
    kdf_params->parameters.salt.present = PBKDF2_Salt_PR_specified;
    ASSERT_RET_OK(asn_ba2OCTSTRING(salt, &kdf_params->parameters.salt.choice.specified));

    ASN_ALLOC(params);
    ASSERT_RET_OK(asn_copy(&PBES2_KDFs_desc, kdf_params, &params->keyDerivationFunc));
    ASSERT_RET_OK(asn_copy(&AlgorithmIdentifier_desc, encr_aid, &params->encryptionScheme));

    ASN_ALLOC(encr_key);
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers, oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers_len,
            &encr_key->encryptionAlgorithm.algorithm));
    ASSERT_RET_OK(asn_create_any(&PBES2_params_desc, params, &encr_key->encryptionAlgorithm.parameters));

    ASSERT_RET(RET_STORAGE_UNSUPPORTED_ENC_SCHEME_ALG, pkcs5_decrypt_dstu(encr_key, pass, &key));
    ASSERT_TRUE(key == NULL);

cleanup:

    BA_FREE(key, salt);
    aid_free(encr_aid);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encr_key);
    ASN_FREE(&PBES2_KDFs_desc, kdf_params);
    ASN_FREE(&PBES2_params_desc, params);
}

static void test_pkcs5_decrypt_dstu_unsup_key_derivation_func_alg(void)
{
    OBJECT_IDENTIFIER_t *algorithm = NULL;
    EncryptedPrivateKeyInfo_t *encr_key = NULL;
    const char *pass = "123456";
    ByteArray *key = NULL;
    unsigned long iterations = 10000;
    ByteArray *salt = ba_alloc_from_le_hex_string("1680D35D1040C58443A2615A841FC813A541D53FB38614536A5BFBD40C6ACE67");
    PBES2_params_t *params = NULL;
    PBES2_KDFs_t *kdf_params = NULL;
    int ret = RET_OK;

    ASN_ALLOC(kdf_params);
    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &algorithm));
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, algorithm, &kdf_params->algorithm));
    ASSERT_RET_OK(asn_ulong2INTEGER(&kdf_params->parameters.iterationCount, iterations));
    kdf_params->parameters.salt.present = PBKDF2_Salt_PR_specified;
    ASSERT_RET_OK(asn_ba2OCTSTRING(salt, &kdf_params->parameters.salt.choice.specified));

    ASN_ALLOC(params);
    ASSERT_RET_OK(asn_copy(&PBES2_KDFs_desc, kdf_params, &params->keyDerivationFunc));

    ASN_ALLOC(encr_key);
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers, oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers_len,
            &encr_key->encryptionAlgorithm.algorithm));
    ASSERT_RET_OK(asn_create_any(&PBES2_params_desc, params, &encr_key->encryptionAlgorithm.parameters));

    ASSERT_RET(RET_STORAGE_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG, pkcs5_decrypt_dstu(encr_key, pass, &key));
    ASSERT_TRUE(key == NULL);

cleanup:

    BA_FREE(key, salt);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encr_key);
    ASN_FREE(&PBES2_KDFs_desc, kdf_params);
    ASN_FREE(&PBES2_params_desc, params);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, algorithm);
}

static void test_pkcs5_decrypt_dstu_unsup_kdf_params_alg(void)
{
    OBJECT_IDENTIFIER_t *algorithm = NULL;
    EncryptedPrivateKeyInfo_t *encr_key = NULL;
    const char *pass = "123456";
    ByteArray *key = NULL;
    unsigned long iterations = 10000;
    ByteArray *salt = ba_alloc_from_le_hex_string("1680D35D1040C58443A2615A841FC813A541D53FB38614536A5BFBD40C6ACE67");
    PBES2_params_t *params = NULL;
    PBES2_KDFs_t *kdf_params = NULL;
    int ret = RET_OK;

    ASN_ALLOC(kdf_params);
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers, oids_get_oid_numbers_by_id(OID_KDF_ID)->numbers_len,
            &kdf_params->algorithm));
    ASSERT_RET_OK(asn_ulong2INTEGER(&kdf_params->parameters.iterationCount, iterations));
    kdf_params->parameters.salt.present = PBKDF2_Salt_PR_specified;
    ASSERT_RET_OK(asn_ba2OCTSTRING(salt, &kdf_params->parameters.salt.choice.specified));
    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &algorithm));
    ASN_ALLOC(kdf_params->parameters.prf);
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, algorithm, &kdf_params->parameters.prf->algorithm));

    ASN_ALLOC(params);
    ASSERT_RET_OK(asn_copy(&PBES2_KDFs_desc, kdf_params, &params->keyDerivationFunc));
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_GOST28147_DSTU_ID)->numbers, oids_get_oid_numbers_by_id(OID_GOST28147_DSTU_ID)->numbers_len,
            &params->encryptionScheme.algorithm));

    ASN_ALLOC(encr_key);
    ASSERT_RET_OK(asn_set_oid(oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers, oids_get_oid_numbers_by_id(OID_PBES2_ID)->numbers_len,
            &encr_key->encryptionAlgorithm.algorithm));
    ASSERT_RET_OK(asn_create_any(&PBES2_params_desc, params, &encr_key->encryptionAlgorithm.parameters));

    ASSERT_RET(RET_STORAGE_UNSUPPORTED_KDF_PARAMS_ALG, pkcs5_decrypt_dstu(encr_key, pass, &key));
    ASSERT_TRUE(key == NULL);

cleanup:

    BA_FREE(key, salt);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encr_key);
    ASN_FREE(&PBES2_KDFs_desc, kdf_params);
    ASN_FREE(&PBES2_params_desc, params);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, algorithm);
}

static void test_pkcs5_encrypt_dstu_unsup_enc_alg(void)
{
    OBJECT_IDENTIFIER_t *algorithm = NULL;
    EncryptedPrivateKeyInfo_t *encr_key = NULL;
    const char *pass = "123456";
    ByteArray *key = ba_alloc_from_le_hex_string("0123456789ABCDEF");
    unsigned long iterations = 10000;
    ByteArray *salt = ba_alloc_from_le_hex_string("1680D35D1040C58443A2615A841FC813A541D53FB38614536A5BFBD40C6ACE67");
    AlgorithmIdentifier_t *encr_aid = aid_alloc();

    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &algorithm));
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, algorithm, &encr_aid->algorithm));

    ASSERT_RET(RET_STORAGE_UNSUPPORTED_ENC_ALG, pkcs5_encrypt_dstu(key, pass, salt, iterations, encr_aid, &encr_key));
    ASSERT_TRUE(encr_key == NULL);

cleanup:

    BA_FREE(key, salt);
    aid_free(encr_aid);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encr_key);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, algorithm);
}

void utest_pkcs5(void)
{
    test_pkcs5_get_type();
    test_pkcs5_get_type_2();
    test_pkcs5_decrypt_dstu_unsup_enc_priv_key_alg();
    test_pkcs5_decrypt_dstu_unsup_enc_scheme_alg();
    test_pkcs5_decrypt_dstu_unsup_key_derivation_func_alg();
    test_pkcs5_decrypt_dstu_unsup_kdf_params_alg();
    test_pkcs5_encrypt_dstu_unsup_enc_alg();
}
