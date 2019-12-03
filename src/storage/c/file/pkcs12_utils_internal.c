/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkcs12_utils_internal.h"

#include "pkcs12.h"
#include "AuthenticatedSafe.h"
#include "SafeBag.h"
#include "CertBag.h"
#include "storage_errors.h"
#include "pkix_utils.h"
#include "asn1_utils.h"
#include "content_info.h"
#include "aid.h"
#include "spki.h"

#include "hmac.h"
#include "rs.h"
#include "PBES2-params.h"
#include "cryptonite_manager.h"

#include "pkix_macros_internal.h"
#include "log_internal.h"
#include "pkcs5.h"
#include "pkcs8.h"

#undef FILE_MARKER
#define FILE_MARKER "storage/pkcs12_utils_internal.c"

const long FRIENDLY_NAME_OID[]           = {1, 2, 840, 113549, 1, 9, 20};

const long X509_CERTIFICATE_OID[]        = {1, 2, 840, 113549, 1, 9, 22, 1};
const long SDSI_CERTIFICATE_OID[]        = {1, 2, 840, 113549, 1, 9, 22, 2};

/** Six types of SafeBags */
const long KEY_BAG_OID[]                 = {1, 2, 840, 113549, 1, 12, 10, 1, 1};
const long PKCS8_SHROUDED_KEY_BAG_OID[]  = {1, 2, 840, 113549, 1, 12, 10, 1, 2};
const long CERT_BAG_OID[]                = {1, 2, 840, 113549, 1, 12, 10, 1, 3};
const long CRL_BAG_OID[]                 = {1, 2, 840, 113549, 1, 12, 10, 1, 4};
const long SECRET_BAG_OID[]              = {1, 2, 840, 113549, 1, 12, 10, 1, 5};
const long SAFE_CONTENTSBAG_OID[]        = {1, 2, 840, 113549, 1, 12, 10, 1, 6};

#define PKCS12_DEFAULT_NAME             "key"

#define PKCS12_DEFAULT_ITERATIONS       10000
#define PKCS12_DEFAULT_SALT_LEN         32

static int pkcs12_pkcs5_params(AlgorithmIdentifier_t *content_encryption_aid, Pkcs5Params **pkcs5_params)
{
    int ret = RET_OK;
    PBES2_params_t *pbes2_params = NULL;
    Pkcs5Params *params = NULL;

    CHECK_PARAM(content_encryption_aid != NULL);
    CHECK_PARAM(pkcs5_params != NULL);

    CALLOC_CHECKED(params, sizeof(Pkcs5Params));

    if (pkix_check_oid_equal(&content_encryption_aid->algorithm, oids_get_oid_numbers_by_id(OID_PBES2_ID))) {
        CHECK_NOT_NULL(pbes2_params = asn_any2type(content_encryption_aid->parameters, &PBES2_params_desc));

        if (!pkix_check_oid_equal(&pbes2_params->keyDerivationFunc.algorithm, oids_get_oid_numbers_by_id(OID_KDF_ID))) {
            SET_ERROR(RET_STORAGE_UNSUPPORTED_KEY_DERIVATION_FUNC_ALG);
        }

        const PBES2_KDFs_t *kdf_params;
        kdf_params = &pbes2_params->keyDerivationFunc;

        DO(asn_OCTSTRING2ba(&kdf_params->parameters.salt.choice.specified, &params->salt));
        DO(asn_INTEGER2ulong(&kdf_params->parameters.iterationCount, &params->iterations));

        CHECK_NOT_NULL(params->encrypt_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &pbes2_params->encryptionScheme));
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_CONTENT_ENC_ALG);
    }

    *pkcs5_params = params;
    params = NULL;

cleanup:

    ASN_FREE(&PBES2_params_desc, pbes2_params);

    if (params) {
        aid_free(params->encrypt_aid);
        ba_free(params->salt);
        free(params);
    }

    return ret;
}

PFX_t *pfx_alloc(void)
{
    PFX_t *container = NULL;
    int ret = RET_OK;

    ASN_ALLOC(container);

cleanup:

    return container;
}

void pfx_free(PFX_t *container)
{
    ASN_FREE(&PFX_desc, container);
}

int pfx_encode(const PFX_t *container, ByteArray **encode)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(encode != NULL);

    DO(asn_encode_ba(&PFX_desc, container, encode));

cleanup:

    return ret;
}

int pfx_decode(PFX_t *container, const ByteArray *encode)
{
    int ret = RET_OK;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(encode != NULL);

    ASN_FREE_CONTENT_PTR(&PFX_desc, container);

    DO(asn_decode_ba(&PFX_desc, container, encode));

cleanup:

    return ret;
}

int pkcs12_create_empty_mac_data(Pkcs12MacType id, int rounds, MacData_t **mac_data)
{
    int ret = RET_OK;

    ByteArray *salt = NULL;
    ByteArray *digest = NULL;
    MacData_t *mac = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    NULL_t *nullptr = NULL;
    HmacCtx *ctx = NULL;
    size_t salt_len;
    size_t digest_len;

    LOG_ENTRY();
    ASN_ALLOC(nullptr);

    switch (id) {
    case KS_FILE_PKCS12_WITH_GOST34311:
        salt_len = 32;
        digest_len = 32;
        DO(aid_create_gost3411(&aid));
        break;
    case KS_FILE_PKCS12_WITH_SHA1:
        salt_len = 8;
        digest_len = 20;
        ASN_ALLOC(aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID), &aid->algorithm));
        break;
    case KS_FILE_PKCS12_WITH_SHA224:
        salt_len = 8;
        digest_len = 28;
        ASN_ALLOC(aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID), &aid->algorithm));
        break;
    case KS_FILE_PKCS12_WITH_SHA256:
        salt_len = 8;
        digest_len = 32;
        ASN_ALLOC(aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID), &aid->algorithm));
        break;
    case KS_FILE_PKCS12_WITH_SHA384:
        salt_len = 8;
        digest_len = 48;
        ASN_ALLOC(aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID), &aid->algorithm));
        break;
    case KS_FILE_PKCS12_WITH_SHA512:
        salt_len = 8;
        digest_len = 64;
        ASN_ALLOC(aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID), &aid->algorithm));
        break;
    default:
        SET_ERROR(RET_STORAGE_UNSUPPORTED_TYPE);
    }
    DO(asn_create_any(&NULL_desc, nullptr, &aid->parameters));
    CHECK_NOT_NULL(salt = ba_alloc_by_len(salt_len));

    DO(rs_std_next_bytes(salt));

    ASN_ALLOC(mac);
    DO(asn_ba2OCTSTRING(salt, &mac->macSalt));
    DO(asn_create_integer_from_long(rounds, &mac->iterations));

    CHECK_NOT_NULL(digest = ba_alloc_by_len(digest_len));
    DO(ba_set(digest, 0));

    DO(asn_ba2OCTSTRING(digest, &mac->mac.digest));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &mac->mac.digestAlgorithm));

    *mac_data = mac;
    mac = NULL;

cleanup:

    ASN_FREE(&MacData_desc, mac);
    ASN_FREE(&NULL_desc, nullptr);
    ba_free(salt);
    ba_free(digest);
    aid_free(aid);
    hmac_free(ctx);

    return ret;
}

int pfx_update_mac_data(PFX_t *pfx, const char *pass)
{
    int ret = RET_OK;
    ByteArray *mac = NULL;

    LOG_ENTRY();

    DO(pfx_calc_mac(pfx, pass, &mac));

    ASN_FREE_CONTENT_STATIC(&Digest_desc, &pfx->macData->mac.digest);
    DO(asn_ba2OCTSTRING(mac, &pfx->macData->mac.digest));

cleanup:

    ba_free(mac);

    return ret;
}

static int pkcs12_key_gen_for_hmac(const AlgorithmIdentifier_t *aid, ByteArray *pass, ByteArray *salt, size_t iter,
        ByteArray **key)
{
    int ret = RET_OK;
    int hash_block_len;
    int id = 3;
    DigestAdapter *da = NULL;
    ByteArray *D = NULL;
    ByteArray *Ai = NULL;
    ByteArray *I = NULL;
    size_t Slen, Plen, Ilen, i;
    size_t passlen, saltlen;
    size_t off;

    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(salt != NULL);
    CHECK_PARAM(key != NULL);

    DO(digest_adapter_init_by_aid(aid, &da));

    if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        hash_block_len = 32;
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {
        hash_block_len = 64;
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
        hash_block_len = 64;
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
        hash_block_len = 64;
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
        hash_block_len = 128;
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
        hash_block_len = 128;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_DIGEST_ALG);
    }

    CHECK_NOT_NULL(D = ba_alloc_by_len(hash_block_len));
    DO(ba_set(D, id));

    saltlen = ba_get_len(salt);
    passlen = ba_get_len(pass);
    Slen = hash_block_len * ((saltlen + hash_block_len - 1) / hash_block_len);
    if (passlen) {
        Plen = hash_block_len * ((passlen + hash_block_len - 1) / hash_block_len);
    } else {
        Plen = 0;
    }

    Ilen = Slen + Plen;
    CHECK_NOT_NULL(I = ba_alloc_by_len(Ilen));
    DO(ba_set(I, 0));

    off = 0;
    for (i = 0; i < Slen / saltlen; i++, off += saltlen) {
        ba_copy(salt, 0, saltlen, I, off);
    }
    if (Slen % saltlen) {
        ba_copy(salt, 0, Slen % saltlen, I, off);
    }

    if (Plen) {
        for (i = 0; i < Plen / passlen; i++, off += passlen) {
            ba_copy(pass, 0, passlen, I, off);
        }
        if (Plen % passlen) {
            ba_copy(pass, 0, Plen % passlen, I, off);
        }
    }

    DO(da->update(da, D));
    DO(da->update(da, I));
    DO(da->final(da, &Ai));

    for (i = 1; i < iter; i++) {
        DO(da->update(da, Ai));
        ba_free(Ai);
        DO(da->final(da, &Ai));
    }

    *key = Ai;
    Ai = NULL;

cleanup:

    digest_adapter_free(da);
    ba_free(D);
    ba_free(I);
    ba_free(Ai);

    return ret;
}

int pfx_calc_mac(const PFX_t *pfx, const char *pass, ByteArray **mac)
{
    int ret = RET_OK;
    ByteArray *salt = NULL;
    ByteArray *dk = NULL;
    ByteArray *hash = NULL;
    ByteArray *sync = NULL;
    ByteArray *data = NULL;
    ByteArray *pass_utf16_ba = NULL;
    unsigned char *pass_utf16_be = NULL;
    size_t pass_utf16_be_len;
    unsigned long iterations;
    HmacCtx *ctx = NULL;

    LOG_ENTRY();

    DO(asn_OCTSTRING2ba(&pfx->macData->macSalt, &salt));
    DO(asn_INTEGER2ulong(pfx->macData->iterations, &iterations));

    if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        CHECK_NOT_NULL(sync = ba_alloc_by_len(32));
        DO(ba_set(sync, 0));
        CHECK_NOT_NULL(ctx = hmac_alloc_gost34_311(GOST28147_SBOX_ID_1, sync));
    } else if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID))) {
        CHECK_NOT_NULL(ctx = hmac_alloc_sha1());
    } else if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID))) {
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_224));
    } else if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID))) {
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_256));
    } else if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_SHA384_ID))) {
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_384));
    } else if (pkix_check_oid_equal(&pfx->macData->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID))) {
        CHECK_NOT_NULL(ctx = hmac_alloc_sha2(SHA2_VARIANT_512));
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_MAC);
    }

    DO(utf8_to_utf16be(pass, &pass_utf16_be, &pass_utf16_be_len));
    CHECK_NOT_NULL(pass_utf16_ba = ba_alloc_from_uint8(pass_utf16_be, pass_utf16_be_len));

    DO(pkcs12_key_gen_for_hmac(&pfx->macData->mac.digestAlgorithm, pass_utf16_ba, salt, iterations, &dk));
    DO(cinfo_get_data(&pfx->authSafe, &data));

    DO(hmac_init(ctx, dk));
    DO(hmac_update(ctx, data));
    DO(hmac_final(ctx, &hash));

    *mac = hash;
    hash = NULL;

cleanup:

    ba_free(salt);
    ba_free(dk);
    ba_free(data);
    ba_free(sync);
    ba_free(hash);
    ba_free(pass_utf16_ba);
    free(pass_utf16_be);

    hmac_free(ctx);

    return ret;
}

int pfx_check_mac(const PFX_t *pfx, const char *pass)
{
    int ret = RET_OK;
    ByteArray *mac = NULL;
    ByteArray *digest = NULL;

    LOG_ENTRY();

    DO(pfx_calc_mac(pfx, pass, &mac))

    DO(asn_OCTSTRING2ba(&pfx->macData->mac.digest, &digest));

    if (ba_cmp(mac, digest)) {
        SET_ERROR(RET_STORAGE_MAC_VERIFY_ERROR);
    }

cleanup:

    ba_free(digest);
    ba_free(mac);

    return ret;
}

Pkcs12Contents **pkcs12_contents_alloc(size_t count)
{
    int ret = RET_OK;
    size_t i;
    Pkcs12Contents **contents = NULL;

    CALLOC_CHECKED(contents, count * sizeof(Pkcs12Contents *));

    for (i = 0; i < count; i++) {
        CALLOC_CHECKED(contents[i], sizeof(Pkcs12Contents));
    }

cleanup:

    if (ret != RET_OK) {
        pkcs12_contents_arr_free(contents, count);
        contents = NULL;
    }

    return contents;
}

void pkcs12_contents_free(Pkcs12Contents *contents)
{
    if (contents) {
        ASN_FREE(&SafeContents_desc, contents->save_contents);
        if (contents->params) {
            ba_free(contents->params->salt);
            ASN_FREE(&AlgorithmIdentifier_desc, contents->params->encrypt_aid);
            free(contents->params);
        }

        free(contents);
    }
}

void pkcs12_contents_arr_free(Pkcs12Contents **contents, size_t count)
{
    size_t i;

    if (contents) {
        for (i = 0; i < count; i++) {
            pkcs12_contents_free(contents[i]);
        }

        free(contents);
    }
}

int pfx_get_contents(const PFX_t *container, const char *password, Pkcs12Contents ***pkcs12_contents, size_t *count)
{
    int ret = RET_OK;
    size_t i;
    size_t cont_count = 0;

    ByteArray *data = NULL;
    AuthenticatedSafe_t *objects = NULL;
    Pkcs12Contents **contents = NULL;
    EncryptedData_t *ecr_data = NULL;
    EncryptedPrivateKeyInfo_t *enc_priv_key_info = NULL;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(pkcs12_contents != NULL);

    DO(cinfo_get_data(&container->authSafe, &data));
    CHECK_NOT_NULL(objects = asn_decode_ba_with_alloc(&AuthenticatedSafe_desc, data));

    if (objects->list.count > 0) {
        cont_count = objects->list.count;
        CHECK_NOT_NULL(contents = pkcs12_contents_alloc(cont_count));

        for (i = 0; i < cont_count; i++) {
            CinfoType type;

            ba_free(data);
            data = NULL;

            DO(cinfo_get_type(objects->list.array[i], &type));
            if (type == CONTENT_DATA) {
                DO(cinfo_get_data(objects->list.array[i], &data));

                contents[i]->params = NULL;
                CHECK_NOT_NULL(contents[i]->save_contents = asn_decode_ba_with_alloc(&SafeContents_desc, data));

            } else if (type == CONTENT_ENCRYPTED) {
                DO(cinfo_get_encrypted_data(objects->list.array[i], &ecr_data));

                DO(pkcs12_pkcs5_params(&ecr_data->encryptedContentInfo.contentEncryptionAlgorithm, &contents[i]->params));

                ASN_ALLOC(enc_priv_key_info);
                DO(asn_copy(&AlgorithmIdentifier_desc,
                        &ecr_data->encryptedContentInfo.contentEncryptionAlgorithm,
                        &enc_priv_key_info->encryptionAlgorithm));
                DO(asn_copy(&OCTET_STRING_desc,
                        ecr_data->encryptedContentInfo.encryptedContent,
                        &enc_priv_key_info->encryptedData));

                DO(pkcs5_decrypt_dstu(enc_priv_key_info, password, &data));
                CHECK_NOT_NULL(contents[i]->save_contents = asn_decode_ba_with_alloc(&SafeContents_desc, data));

                ASN_FREE(&EncryptedPrivateKeyInfo_desc, enc_priv_key_info);
                enc_priv_key_info = NULL;

                ASN_FREE(&EncryptedData_desc, ecr_data);
                ecr_data = NULL;

            } else {
                SET_ERROR(RET_STORAGE_UNSUPPORTED_CINFO_TYPE);
            }
        }
    }

    *pkcs12_contents = contents;
    *count = cont_count;

cleanup:

    ba_free(data);

    ASN_FREE(&AuthenticatedSafe_desc, objects);
    ASN_FREE(&EncryptedData_desc, ecr_data);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, enc_priv_key_info);

    if (ret != RET_OK) {
        pkcs12_contents_arr_free(contents, cont_count);
    }

    return ret;
}

int safebag_get_alias(const SafeBag_t *bag, int idx, char **alias)
{
    int ret = RET_OK;

    OBJECT_IDENTIFIER_t *alias_oid = NULL;
    BMPString_t *alias_bs = NULL;
    Attribute_t *alias_attr = NULL;
    char *name = NULL;

    CHECK_PARAM(alias != NULL);

    if (bag->bagAttributes) {
        DO(asn_create_oid(FRIENDLY_NAME_OID, sizeof(FRIENDLY_NAME_OID) / sizeof(FRIENDLY_NAME_OID[0]), &alias_oid));
        if (get_attr_by_oid(bag->bagAttributes, alias_oid, &alias_attr) == RET_OK) {
            if (alias_attr->value.list.count > 0) {
                CHECK_NOT_NULL(alias_bs = asn_any2type(alias_attr->value.list.array[0], &BMPString_desc));
            }
        }
    }

    if (alias_bs) {
        DO(utf16be_to_utf8(alias_bs->buf, alias_bs->size, &name));
    } else {
        MALLOC_CHECKED(name, strlen(PKCS12_DEFAULT_NAME) + 3 + 1);
        sprintf(name, "%s%i", PKCS12_DEFAULT_NAME, (uint8_t)(idx + 1));
    }

    *alias = name;

cleanup:

    ASN_FREE(&BMPString_desc, alias_bs);
    ASN_FREE(&Attribute_desc, alias_attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, alias_oid);

    if (ret != RET_OK) {
        free(name);
    }

    return ret;
}

int safebag_get_type(const SafeBag_t *bag, Pkcs12BagType_t *type)
{
    int ret = RET_OK;

    CHECK_PARAM(bag != NULL);
    CHECK_PARAM(type != NULL);

    if (asn_check_oid_equal(&bag->bagId, KEY_BAG_OID, sizeof(KEY_BAG_OID) / sizeof(KEY_BAG_OID[0]))) {
        *type = KEY_BAG;
    } else if (asn_check_oid_equal(&bag->bagId, PKCS8_SHROUDED_KEY_BAG_OID,
            sizeof(PKCS8_SHROUDED_KEY_BAG_OID) / sizeof(PKCS8_SHROUDED_KEY_BAG_OID[0]))) {
        *type = PKCS8SHROUDEDKEY_BAG;
    } else if (asn_check_oid_equal(&bag->bagId, CERT_BAG_OID, sizeof(CERT_BAG_OID) / sizeof(CERT_BAG_OID[0]))) {
        *type = CERT_BAG;
    } else if (asn_check_oid_equal(&bag->bagId, CRL_BAG_OID, sizeof(CRL_BAG_OID) / sizeof(CRL_BAG_OID[0]))) {
        *type = CRL_BAG;
    } else if (asn_check_oid_equal(&bag->bagId, SECRET_BAG_OID, sizeof(SECRET_BAG_OID) / sizeof(SECRET_BAG_OID[0]))) {
        *type = SECRET_BAG;
    } else if (asn_check_oid_equal(&bag->bagId, SAFE_CONTENTSBAG_OID,
            sizeof(SAFE_CONTENTSBAG_OID) / sizeof(SAFE_CONTENTSBAG_OID[0]))) {
        *type = SAFECONTENTS_BAG;
    } else {
        SET_ERROR(RET_STORAGE_UNSUPPORTED_SAFE_BAG_ALG);
    }

cleanup:

    return ret;
}

int pkcs12_contents_get_certificates(const Pkcs12Contents **contents, size_t contents_len, ByteArray ***certs)
{
    int ret = RET_OK;
    size_t i, count;
    int j;
    CertBag_t *cert_bag = NULL;
    OCTET_STRING_t *data = NULL;
    ByteArray **certificates = NULL;

    LOG_ENTRY();

    CHECK_PARAM(contents != NULL);
    CHECK_PARAM(certs != NULL);

    CALLOC_CHECKED(certificates, sizeof(ByteArray *));

    count = 0;
    for (i = 0; i < contents_len; i ++) {
        for (j = 0; j < contents[i]->save_contents->list.count; j++) {
            Pkcs12BagType_t type;
            SafeBag_t *safebag = contents[i]->save_contents->list.array[j];

            DO(safebag_get_type(safebag, &type));
            if (type == CERT_BAG) {
                CHECK_NOT_NULL(cert_bag = asn_any2type(&safebag->bagValue, &CertBag_desc));
                if (asn_check_oid_equal(&cert_bag->certId,
                        X509_CERTIFICATE_OID,
                        sizeof(X509_CERTIFICATE_OID) / sizeof(X509_CERTIFICATE_OID[0]))) {

                } else if (asn_check_oid_equal(&cert_bag->certId, SDSI_CERTIFICATE_OID,
                        sizeof(SDSI_CERTIFICATE_OID) / sizeof(SDSI_CERTIFICATE_OID[0]))) {

                } else {
                    SET_ERROR(RET_STORAGE_UNSUPPORTED_CERT_BAG_ALG);
                }

                CHECK_NOT_NULL(data = asn_any2type(&cert_bag->certValue, &OCTET_STRING_desc));

                REALLOC_CHECKED(certificates, (count + 2) * sizeof(ByteArray *),certificates);
                DO(asn_OCTSTRING2ba(data, &certificates[count]))

                ASN_FREE(&OCTET_STRING_desc, data);
                data = NULL;

                ASN_FREE(&CertBag_desc, cert_bag);
                cert_bag = NULL;

                count++;
            }
        }
    }

    certificates[count] = NULL;

    *certs = certificates;

cleanup:

    ASN_FREE(&OCTET_STRING_desc, data);
    ASN_FREE(&CertBag_desc, cert_bag);

    return ret;
}

int pkcs12_contents_set_key(const char *alias, const char *pass, const PrivateKeyInfo_t *key, int rounds,
        Pkcs12Contents *contents)
{
    int ret = RET_OK;
    ByteArray *encoded = NULL;
    ByteArray *salt = NULL;
    EncryptedPrivateKeyInfo_t *encrypt_key = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    SafeBag_t *safebag = NULL;
    Attribute_t *alias_attr = NULL;
    BMPString_t *alias_bs = NULL;
    uint8_t *alias_be = NULL;

    ByteArray *key_id = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    OCTET_STRING_t *local_key_id_os = NULL;

    LOG_ENTRY();

    CHECK_PARAM(contents != NULL);
    CHECK_PARAM(key != NULL);

    ASN_ALLOC(safebag);

    if (pass != NULL) {
        DO(pkcs8_encode(key, &encoded));

        CHECK_NOT_NULL(salt = ba_alloc_by_len(PKCS12_DEFAULT_SALT_LEN));
        DO(rs_std_next_bytes(salt));
        DO(aid_create_gost28147_cfb(&aid));
        DO(pkcs5_encrypt_dstu(encoded, pass, salt, rounds, aid, &encrypt_key));

        DO(asn_set_oid(PKCS8_SHROUDED_KEY_BAG_OID,
                sizeof(PKCS8_SHROUDED_KEY_BAG_OID) / sizeof(PKCS8_SHROUDED_KEY_BAG_OID[0]),
                &safebag->bagId));

        DO(asn_set_any(&EncryptedPrivateKeyInfo_desc, encrypt_key, &safebag->bagValue));

    } else {
        DO(asn_set_oid(KEY_BAG_OID,
                sizeof(KEY_BAG_OID) / sizeof(KEY_BAG_OID[0]),
                &safebag->bagId));

        DO(asn_set_any(&PrivateKeyInfo_desc, key, &safebag->bagValue));
    }

    /* Add localKeyID (1.2.840.113549.1.9.21) */
    DO(pkcs8_get_spki(key, &spki));
    DO(pkix_get_key_id_from_spki(spki, &key_id));
    ASN_ALLOC(local_key_id_os);
    DO(asn_ba2OCTSTRING(key_id, local_key_id_os));
    DO(init_attr(&alias_attr, oids_get_oid_numbers_by_id(OID_LOCALKEY_ID), &OCTET_STRING_desc, local_key_id_os));

    ASN_ALLOC(safebag->bagAttributes);
    ASN_SET_ADD(&safebag->bagAttributes->list, alias_attr);
    alias_attr = NULL;

    /* Add friendlyName (1.2.840.113549.1.9.20) */
    if (alias) {
        size_t len = 0;

        DO(utf8_to_utf16be(alias, &alias_be, &len));
        ASN_ALLOC(alias_bs);
        DO(asn_bytes2OCTSTRING(alias_bs, alias_be, len));
        DO(init_attr(&alias_attr, oids_get_oid_numbers_by_id(OID_FRIENDLYNAME_ID), &BMPString_desc, alias_bs));

        ASN_SET_ADD(&safebag->bagAttributes->list, alias_attr);
        alias_attr = NULL;
    }

    contents->params = NULL;

    ASN_ALLOC(contents->save_contents);

    ASN_SEQUENCE_ADD(&contents->save_contents->list, safebag);
    safebag = NULL;

cleanup:

    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encrypt_key);
    ASN_FREE(&SafeBag_desc, safebag);
    ASN_FREE(&Attribute_desc, alias_attr);
    ASN_FREE(&BMPString_desc, alias_bs);
    ASN_FREE(&OCTET_STRING_desc, local_key_id_os);
    spki_free(spki);
    ba_free(key_id);

    aid_free(aid);

    ba_free(salt);
    ba_free(encoded);

    free(alias_be);

    return ret;
}

int pkcs12_contents_set_certs(const ByteArray **certs, Pkcs12Contents *contents)
{
    int ret = RET_OK;
    int i;
    SafeBag_t *safebag = NULL;
    CertBag_t *cert_bag = NULL;
    OCTET_STRING_t *data = NULL;

    LOG_ENTRY();

    CHECK_PARAM(contents != NULL);
    CHECK_PARAM(certs != NULL);

    ASN_ALLOC(contents->save_contents);
    ASN_ALLOC(cert_bag);

    i = 0;
    while (certs[i] != NULL) {
        DO(asn_create_octstring_from_ba(certs[i], &data));

        DO(asn_set_oid(X509_CERTIFICATE_OID,
                sizeof(X509_CERTIFICATE_OID) / sizeof(X509_CERTIFICATE_OID[0]),
                &cert_bag->certId));
        DO(asn_set_any(&OCTET_STRING_desc, data, &cert_bag->certValue));

        ASN_ALLOC(safebag);
        DO(asn_set_oid(CERT_BAG_OID, sizeof(CERT_BAG_OID) / sizeof(CERT_BAG_OID[0]), &safebag->bagId));
        DO(asn_set_any(&CertBag_desc, cert_bag, &safebag->bagValue));

        ASN_SEQUENCE_ADD(&contents->save_contents->list, safebag);
        safebag = NULL;

        ASN_FREE(&OCTET_STRING_desc, data);
        data = NULL;

        i++;
    }

    contents->params = NULL;

cleanup:

    ASN_FREE(&OCTET_STRING_desc, data);
    ASN_FREE(&SafeBag_desc, safebag);
    ASN_FREE(&CertBag_desc, cert_bag);

    return ret;
}

