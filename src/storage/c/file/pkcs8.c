/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkcs8.h"

#include "ECPrivateKey.h"
#include "asn1_utils.h"
#include "cryptonite_manager.h"
#include "storage_errors.h"
#include "pkix_utils.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "cert.h"
#include "aid.h"
#include "spki.h"
#include "oids.h"
#include "rs.h"
#include "ecdsa.h"


#undef FILE_MARKER
#define FILE_MARKER "storage/pkcs8.c"

/** OID DSA key. */
const long DSA_KEY_OID[6]            = {1, 2, 840, 10040, 4, 1};
/** OID RSA key. */
const long RSA_KEY_OID[7]            = {1, 2, 840, 113549, 1, 1, 1};
/** OID ECDSA key. */
const long ECDSA_KEY1_OID[]          = {1, 2, 840, 10045, 2, 1};
const long ECDSA_KEY2_OID[]          = {1, 3, 132, 0, 34};

/** OID IIT KEP key params. */
const long IIT_KEP_PARAMS_OID[11]   = {1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 2};
/** OID IIT KEP key. */
const long IIT_KEP_KEY_OID[11]      = {1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 3};
/** OID IIT SubjectKeyIdentifier of KEP key. */
const long IIT_KEP_SUBJ_KEY_ID[11]  = {1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 5};
const long IIT_ENC_KEY_ID[11]       = {1, 3, 6, 1, 4, 1, 19398, 1, 1, 2, 6};

/**
 * Переворачивает биты в байте.
 */
static uint8_t swap_bits(uint8_t byte)
{
    int i;
    unsigned char res = 0;

    for (i = 0; i < 8; i++) {
        res |= ((byte >> i) & 0x01) << (7 - i);
    }

    return res;
}

PrivateKeyInfo_t *pkcs8_alloc(void)
{
    PrivateKeyInfo_t *key = NULL;
    int ret = RET_OK;

    ASN_ALLOC(key);

cleanup:

    return key;
}

void pkcs8_free(PrivateKeyInfo_t *key)
{
    if (key) {
        memset(key->privateKey.buf, 0x00, key->privateKey.size);
        ASN_FREE(&PrivateKeyInfo_desc, key);
    }
}

int pkcs8_generate(const AlgorithmIdentifier_t *aid, PrivateKeyInfo_t **key)
{
    int ret = RET_OK;

    PrivateKeyInfo_t *privkey = NULL;
    Dstu4145Ctx *params = NULL;
    EcdsaCtx *ecdsa_ctx = NULL;
    ECPrivateKey_t *ec_privkey = NULL;
    PrngCtx *prng = NULL;
    Pkcs8PrivatekeyType type;
    ByteArray *seed = NULL;
    ByteArray *d = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    ByteArray *ec_privkey_ba = NULL;
    ByteArray *q = NULL;

    LOG_ENTRY();
    CHECK_PARAM(key != NULL);
    CHECK_PARAM(aid != NULL);

    ASN_ALLOC(privkey);
    ASN_ALLOC(ec_privkey);

    DO(asn_long2INTEGER(&privkey->version, 0));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &privkey->privateKeyAlgorithm));
    DO(pkcs8_type(privkey, &type));

    switch (type) {
    case PRIVATEKEY_DSTU:
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(rs_std_next_bytes(seed));
        CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));
        DO(aid_get_dstu4145_params(aid, &params));
        DO(dstu4145_generate_privkey(params, prng, &d));
        DO(asn_ba2OCTSTRING(d, &privkey->privateKey));
        break;
    case PRIVATEKEY_ECDSA:
        CHECK_NOT_NULL(seed = ba_alloc_by_len(40));
        DO(rs_std_next_bytes(seed));
        CHECK_NOT_NULL(prng = prng_alloc(PRNG_MODE_DEFAULT, seed));
        DO(aid_get_ecdsa_params(&privkey->privateKeyAlgorithm, &ecdsa_ctx));
        DO(ecdsa_generate_privkey(ecdsa_ctx, prng, &d));
        DO(ecdsa_get_pubkey(ecdsa_ctx, d, &qx, &qy));
        CHECK_NOT_NULL(q = ba_alloc_by_len(1));
        DO(ba_set(q, 0x04));
        //Стандартная форма ключа ECDSA - le
        DO(ba_swap(qx));
        DO(ba_swap(qy));
        DO(ba_append(qx, 0, 0, q));
        DO(ba_append(qy, 0, 0, q));
        DO(ba_swap(d));
        DO(asn_ba2OCTSTRING(d, &ec_privkey->privateKey));
        ASN_ALLOC(ec_privkey->publicKey);
        DO(asn_ba2BITSTRING(q, ec_privkey->publicKey));
        DO(asn_ulong2INTEGER(&ec_privkey->version, Version_v2));
        DO(asn_encode_ba(&ECPrivateKey_desc, ec_privkey, &ec_privkey_ba));
        DO(asn_ba2OCTSTRING(ec_privkey_ba, &privkey->privateKey));
        break;
    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

    *key = privkey;
    privkey = NULL;

cleanup:

    ba_free(seed);
    ba_free(qy);
    ba_free(qx);
    ba_free(q);
    ba_free(ec_privkey_ba);
    ba_free_private(d);
    ecdsa_free(ecdsa_ctx);
    dstu4145_free(params);
    prng_free(prng);
    pkcs8_free(privkey);
    ASN_FREE(&ECPrivateKey_desc, ec_privkey);

    return ret;
}

int pkcs8_init(PrivateKeyInfo_t *key, const ByteArray *privkey, const AlgorithmIdentifier_t *aid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(privkey != NULL);
    CHECK_PARAM(aid != NULL);

    ASN_FREE_CONTENT_PTR(&PrivateKeyInfo_desc, key);

    DO(asn_long2INTEGER(&key->version, 0L));
    DO(asn_ba2OCTSTRING(privkey, &key->privateKey));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &key->privateKeyAlgorithm));

cleanup:

    return ret;
}

int pkcs8_encode(const PrivateKeyInfo_t *key, ByteArray **encode)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(encode != NULL);

    DO(asn_encode_ba(&PrivateKeyInfo_desc, key, encode));

cleanup:

    return ret;
}

int pkcs8_decode(PrivateKeyInfo_t *key, const ByteArray *encode)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(encode != NULL);

    ASN_FREE_CONTENT_PTR(&PrivateKeyInfo_desc, key);

    DO(asn_decode_ba(&PrivateKeyInfo_desc, key, encode));

cleanup:

    return ret;
}

int pkcs8_type(const PrivateKeyInfo_t *key, Pkcs8PrivatekeyType *type)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(type != NULL);

    if (asn_check_oid_equal(&key->privateKeyAlgorithm.algorithm, DSA_KEY_OID,
            sizeof(DSA_KEY_OID) / sizeof(DSA_KEY_OID[0]))) {
        *type = PRIVATEKEY_DSA;
    } else if (asn_check_oid_equal(&key->privateKeyAlgorithm.algorithm, RSA_KEY_OID,
            sizeof(RSA_KEY_OID) / sizeof(RSA_KEY_OID[0]))) {
        *type = PRIVATEKEY_RSA;
    } else if (pkix_check_oid_parent(&key->privateKeyAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {
        *type = PRIVATEKEY_DSTU;
    } else if (pkix_check_oid_equal(&key->privateKeyAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID))) {
        *type = PRIVATEKEY_ECDSA;
    } else if (pkix_check_oid_equal(&key->privateKeyAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_GOST3410_ID))) {
        *type = PRIVATEKEY_GOST3410;
    } else {
        *type = PRIVATEKEY_UNKNOWN;
    }
cleanup:
    return ret;
}

int pkcs8_get_privatekey(const PrivateKeyInfo_t *key, ByteArray **privatekey)
{
    int ret = RET_OK;
    Pkcs8PrivatekeyType type;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(privatekey != NULL);

    DO(pkcs8_type(key, &type));

    if (type == PRIVATEKEY_DSTU) {
        DO(asn_OCTSTRING2ba(&key->privateKey, privatekey));

    } else if (type == PRIVATEKEY_ECDSA) {
        ByteArray *tmp = NULL;
        OBJECT_IDENTIFIER_t *oid = NULL;

        //Для ECDSA всегда должен идти оид кривой.
        if (key->privateKeyAlgorithm.parameters == NULL) {
            SET_ERROR(RET_INVALID_PRIVATE_KEY);
        }

        CHECK_NOT_NULL(oid = asn_any2type(key->privateKeyAlgorithm.parameters, &OBJECT_IDENTIFIER_desc));

        DO(asn_OCTSTRING2ba(&key->privateKey, &tmp));
        //8 - число октетов, окторые кодируют длинну BITSTRING и OCTETSTRING
        if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_192_R1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 24));
        } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_224_R1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 28));
        } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_256_R1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 32));
        } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_384_R1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 48));
        } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_521_R1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 66));
        } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_ECDSA_SECP_256_K1_ID))) {
            CHECK_NOT_NULL(*privatekey = ba_copy_with_alloc(tmp, 8, 32));
        }
        DO(ba_swap(*privatekey));
        ba_free(tmp);
        ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

cleanup:

    return ret;
}

int pkcs8_get_kep_privatekey(const PrivateKeyInfo_t *private_key, ByteArray **d)
{
    int ret = RET_OK;
    size_t i;

    BIT_STRING_t *bs_kep_key = NULL;
    Attribute_t *kep_key_attr = NULL;
    OBJECT_IDENTIFIER_t *kep_key_oid = NULL;

    ByteArray *key = NULL;
    uint8_t *buf;

    LOG_ENTRY();

    CHECK_PARAM(d != NULL);
    CHECK_PARAM(private_key != NULL);

    DO(asn_create_oid(IIT_KEP_KEY_OID, sizeof(IIT_KEP_KEY_OID) / sizeof(IIT_KEP_KEY_OID[0]), &kep_key_oid));
    DO(get_attr_by_oid(private_key->attributes, kep_key_oid, &kep_key_attr));

    if (kep_key_attr->value.list.count > 0) {
        CHECK_NOT_NULL(bs_kep_key = asn_any2type(kep_key_attr->value.list.array[0], &BIT_STRING_desc));
    } else {
        SET_ERROR(RET_STORAGE_INVALID_KEP_KEY_ATTR);
    }

    DO(asn_BITSTRING2ba(bs_kep_key, &key));

    DO(ba_swap(key));
    buf = (uint8_t *)ba_get_buf(key);
    for (i = 0; i < ba_get_len(key); i++) {
        buf[i] = swap_bits(buf[i]);
    }

    *d = key;

cleanup:

    ASN_FREE(&BIT_STRING_desc, bs_kep_key);
    ASN_FREE(&Attribute_desc, kep_key_attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, kep_key_oid);

    if (ret != RET_OK) {
        ba_free(key);
    }

    return ret;
}

int pkcs8_get_spki(const PrivateKeyInfo_t *key, SubjectPublicKeyInfo_t **spki)
{
    int ret = RET_OK;
    Pkcs8PrivatekeyType type;
    ByteArray *privatekey = NULL;
    ByteArray *pubkey = NULL;
    ByteArray *q = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;
    Dstu4145Ctx *cryptos_dstu_params = NULL;
    EcdsaCtx *ecdsa_params = NULL;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(spki != NULL);

    DO(pkcs8_type(key, &type));

    switch (type) {
    case PRIVATEKEY_DSTU:
        DO(pkcs8_get_privatekey(key, &privatekey));

        DO(aid_get_dstu4145_params(&key->privateKeyAlgorithm, &cryptos_dstu_params));
        DO(dstu4145_get_pubkey(cryptos_dstu_params, privatekey, &qx, &qy));
        DO(dstu4145_compress_pubkey(cryptos_dstu_params, qx, qy, &pubkey));

        DO(create_dstu4145_spki(&key->privateKeyAlgorithm.algorithm,
                cryptos_dstu_params,
                NULL,
                pubkey,
                spki));
        break;

    case PRIVATEKEY_ECDSA:
        DO(pkcs8_get_privatekey(key, &privatekey));

        DO(aid_get_ecdsa_params(&key->privateKeyAlgorithm, &ecdsa_params));
        DO(ecdsa_get_pubkey(ecdsa_params, privatekey, &qx, &qy));
        DO(ba_swap(qx));
        DO(ba_swap(qy));
        CHECK_NOT_NULL(q = ba_alloc_by_len(1));
        DO(ba_set(q, 0x04));
        CHECK_NOT_NULL(pubkey = ba_join(qx, qy));
        DO(ba_append(pubkey, 0, 0, q));
        DO(create_ecdsa_spki(&key->privateKeyAlgorithm.algorithm, key->privateKeyAlgorithm.parameters, ecdsa_params, q, spki));
        break;

    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

cleanup:

    ecdsa_free(ecdsa_params);
    ba_free(privatekey);
    ba_free(pubkey);
    ba_free(qx);
    ba_free(qy);
    ba_free(q);
    dstu4145_free(cryptos_dstu_params);

    return ret;
}

int pkcs8_get_sign_adapter(const PrivateKeyInfo_t *key,
        const ByteArray *cert,
        SignAdapter **sa)
{
    ByteArray *privatekey = NULL;
    Certificate_t *asn_cert = NULL;
    AlgorithmIdentifier_t *signature_aid = NULL;
    int ret = RET_OK;
    Pkcs8PrivatekeyType type;

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(sa != NULL);

    DO(pkcs8_type(key, &type));

    switch (type) {
    case PRIVATEKEY_DSTU:
        DO(pkcs8_get_privatekey(key, &privatekey));

        if (cert == NULL) {
            DO(sign_adapter_init_by_aid(privatekey, &key->privateKeyAlgorithm, &key->privateKeyAlgorithm, sa));
        } else {
            CHECK_NOT_NULL(asn_cert = cert_alloc());
            DO(cert_decode(asn_cert, cert));

            DO(sign_adapter_init_by_cert(privatekey, asn_cert, sa));
        }
        break;

    case PRIVATEKEY_ECDSA:
        DO(pkcs8_get_privatekey(key, &privatekey));
        ASN_ALLOC(signature_aid);
        DO(aid_init_by_oid(signature_aid, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)));

        if (cert == NULL) {
            DO(sign_adapter_init_by_aid(privatekey, signature_aid, &key->privateKeyAlgorithm, sa));
        } else {
            CHECK_NOT_NULL(asn_cert = cert_alloc());
            DO(cert_decode(asn_cert, cert));

            DO(sign_adapter_init_by_cert(privatekey, asn_cert, sa));
        }
        break;

    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

cleanup:

    aid_free(signature_aid);
    ba_free(privatekey);
    cert_free(asn_cert);

    return ret;
}

int pkcs8_get_dh_adapter(const PrivateKeyInfo_t *key, DhAdapter **ctx)
{
    int ret = RET_OK;
    Pkcs8PrivatekeyType type;
    ByteArray *priv_key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(ctx != NULL);

    DO(pkcs8_type(key, &type));

    switch (type) {
    case PRIVATEKEY_ECDSA:
    case PRIVATEKEY_DSTU:
        DO(pkcs8_get_privatekey(key, &priv_key));
        DO(dh_adapter_init(priv_key, &key->privateKeyAlgorithm, ctx));

        break;

    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

cleanup:

    ba_free(priv_key);

    return ret;
}

int pkcs8_get_verify_adapter(const PrivateKeyInfo_t *key, VerifyAdapter **va)
{
    int ret = RET_OK;
    Pkcs8PrivatekeyType type;
    SubjectPublicKeyInfo_t *spki = NULL;
    AlgorithmIdentifier_t *signature_aid = NULL;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(va != NULL);

    DO(pkcs8_type(key, &type));

    switch (type) {
    case PRIVATEKEY_ECDSA:
        ASN_ALLOC(signature_aid);

        DO(aid_init_by_oid(signature_aid, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)));

        DO(pkcs8_get_spki(key, &spki));
        DO(verify_adapter_init_by_spki(signature_aid, spki, va));
        break;

    case PRIVATEKEY_DSTU:
        DO(pkcs8_get_spki(key, &spki));
        DO(verify_adapter_init_by_spki(&key->privateKeyAlgorithm, spki, va));
        break;

    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_PRIV_KEY_TYPE);
    }

cleanup:

    aid_free(signature_aid);
    spki_free(spki);

    return ret;
}

int pkcs8_add_attr(PrivateKeyInfo_t *key, const Attribute_t *attr)
{
    int ret = RET_OK;
    Attribute_t *attribute = NULL;

    LOG_ENTRY();

    CHECK_PARAM(key != NULL);
    CHECK_PARAM(attr != NULL);

    CHECK_NOT_NULL(attribute = asn_copy_with_alloc(&Attribute_desc, attr));

    if (!key->attributes) {
        ASN_ALLOC(key->attributes);
    }

    DO(ASN_SET_ADD(&key->attributes->list, attribute));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Attribute_desc, attribute);
    }

    return ret;
}
