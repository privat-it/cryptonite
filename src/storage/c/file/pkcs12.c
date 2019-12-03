/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkcs12.h"

#include "storage_errors.h"
#include "pkix_utils.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "cert.h"
#include "spki.h"
#include "cert_store.h"
#include "rs.h"
#include "dstu4145.h"
#include "gost28147.h"
#include "aid.h"
#include "AuthenticatedSafe.h"
#include "content_info.h"
#include "pkcs12_utils_internal.h"
#include "pkcs5.h"
#include "pkcs8.h"

#define GENKEY_ID    -1

#undef FILE_MARKER
#define FILE_MARKER "storage/pkcs12.c"

/* Внутренний контекст хранилища. */
struct Pkcs12StorageCtx_st {
    Pkcs12IntStorage *owner;
    Pkcs12Keypair    *kprs;
    size_t            kprs_cnt;
    PrivateKeyInfo_t *genkey;
    PrivateKeyInfo_t *curr_key;
};

int pkcs12_get_storage_name(const Pkcs12Ctx *this, const char *const *name)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(name != NULL);

    *((const char **)name) = this->owner->name;

cleanup:
    return ret;
}

int pkcs12_change_password(Pkcs12Ctx *this, const char *old_pass, const char *new_pass)
{
    int ret = RET_OK;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(old_pass != NULL);
    CHECK_PARAM(new_pass != NULL);

    if (!strcmp(old_pass, this->owner->password)) {
        free(this->owner->password);
        MALLOC_CHECKED(this->owner->password, strlen(new_pass) + 1);
        strcpy(this->owner->password, new_pass);
    }

cleanup:

    return ret;
}

int pkcs12_enum_keys(Pkcs12Ctx *this, const Pkcs12Keypair *const *keys, const size_t *cnt)
{
    int ret = RET_OK;
    int j, count;
    size_t i;
    char *alias = NULL;
    ByteArray *data = NULL;
    PrivateKeyInfo_t *key = NULL;
    EncryptedPrivateKeyInfo_t *encrypted_key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(this != NULL);

    for (i = 0; i < this->kprs_cnt; i++) {
        free(*(char **)&this->kprs[i].alias);
        *(char **)&this->kprs[i].alias = NULL;
    }

    count = 0;
    for (i = 0; i < this->owner->contents_len; i++) {
        for (j = 0; j < this->owner->contents[i]->save_contents->list.count; j++) {
            Pkcs12BagType_t type;
            SafeBag_t *safebag = this->owner->contents[i]->save_contents->list.array[j];

            DO(safebag_get_type(safebag, &type));
            if (type == KEY_BAG) {
                REALLOC_CHECKED(this->kprs, (count + 1) * sizeof(Pkcs12Keypair), this->kprs);
                DO(safebag_get_alias(safebag, count, &alias));

                *(char **)&this->kprs[count].alias = alias;
                *(int *)&this->kprs[count].int_id = count;
                *(Pkcs12AuthType *)&this->kprs[count].auth = AUTH_NO_PASS;

                count++;
                alias = NULL;
            }

            if (type == PKCS8SHROUDEDKEY_BAG) {
                REALLOC_CHECKED(this->kprs, (count + 1) * sizeof(Pkcs12Keypair), this->kprs);
                DO(safebag_get_alias(safebag, count, &alias));

                CHECK_NOT_NULL(encrypted_key = asn_any2type(&safebag->bagValue, &EncryptedPrivateKeyInfo_desc));
                DO(pkcs5_decrypt_dstu(encrypted_key, this->owner->password, &data));

                key = asn_decode_ba_with_alloc(&PrivateKeyInfo_desc, data);
                if (key == NULL) {
                    *(Pkcs12AuthType *)&this->kprs[count].auth = AUTH_KEY_PASS;
                } else {
                    *(Pkcs12AuthType *)&this->kprs[count].auth = AUTH_STORAGE_PASS;
                }

                *(char **)&this->kprs[count].alias = alias;
                *(int *)&this->kprs[count].int_id = count;

                ASN_FREE(&EncryptedPrivateKeyInfo_desc, encrypted_key);
                encrypted_key = NULL;
                pkcs8_free(key);
                key = NULL;
                ba_free(data);
                data = NULL;

                count++;
                alias = NULL;
            }
        }
    }

    this->kprs_cnt = count;

    if (keys != NULL) {
        *(Pkcs12Keypair **)keys = this->kprs;
    }

    if (cnt != NULL) {
        *(size_t *)cnt = this->kprs_cnt;
    }

cleanup:

    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encrypted_key);
    pkcs8_free(key);
    ba_free(data);
    free(alias);

    return ret;
}

/**
 * Получает ключ по имени из списка.
 *
 * @param alias пользовательское имя ключа
 * @param keys список ключей
 * @param cnt количество ключей в списке
 *
 * @return найденный ключ или NULL, если заданное имя отсутствует
 */
static const Pkcs12Keypair *store_alias2key(const char *alias, const Pkcs12Keypair *keys, size_t cnt)
{
    if (alias && keys) {
        while (cnt--) {
            if (!strcmp(alias, keys[cnt].alias)) {
                return &keys[cnt];
            }
        }
    }

    return NULL;
}

int pkcs12_select_key(Pkcs12Ctx *this, const char *alias, const char *pwd)
{
    int ret = RET_OK;
    size_t i, count;
    PrivateKeyInfo_t *privkey = NULL;
    EncryptedPrivateKeyInfo_t *encrypted_key = NULL;
    ByteArray *data = NULL;
    int j;
    const Pkcs12Keypair *key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(this != NULL);

    if (this->kprs == NULL || this->kprs_cnt == 0) {
        DO(pkcs12_enum_keys(this, NULL, NULL))
    }

    if (alias != NULL) {
        key = store_alias2key(alias, this->kprs, this->kprs_cnt);
    } else {
        if (this->kprs != NULL && this->kprs_cnt > 0) {
            key = &this->kprs[0];
        }
    }

    if (key == NULL) {
        SET_ERROR(RET_STORAGE_NO_KEY);
    }

    count = 0;
    for (i = 0; i < this->owner->contents_len; i ++) {
        for (j = 0; j < this->owner->contents[i]->save_contents->list.count; j++) {
            Pkcs12BagType_t type;
            SafeBag_t *safebag = this->owner->contents[i]->save_contents->list.array[j];

            DO(safebag_get_type(safebag, &type));
            if (type == KEY_BAG) {
                if ((int)count == key->int_id) {
                    CHECK_NOT_NULL(privkey = asn_any2type(&safebag->bagValue, &PrivateKeyInfo_desc));
                    goto selected;
                }

                count++;
            }

            if (type == PKCS8SHROUDEDKEY_BAG) {
                if ((int)count == key->int_id) {
                    CHECK_NOT_NULL(encrypted_key = asn_any2type(&safebag->bagValue, &EncryptedPrivateKeyInfo_desc));
                    if (pwd) {
                        DO(pkcs5_decrypt_dstu(encrypted_key, pwd, &data));
                    } else {
                        DO(pkcs5_decrypt_dstu(encrypted_key, this->owner->password, &data));
                    }

                    privkey = asn_decode_ba_with_alloc(&PrivateKeyInfo_desc, data);

                    if (privkey == NULL) {
                        SET_ERROR(RET_STORAGE_INVALID_KEY_PASSWORD);
                    } else {
                        goto selected;
                    }
                }

                count++;
            }
        }
    }

selected:

    pkcs8_free(this->curr_key);
    this->curr_key = privkey;
    privkey = NULL;

cleanup:

    ba_free(data);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, encrypted_key);
    ASN_FREE(&PrivateKeyInfo_desc, privkey);

    return ret;
}

int pkcs12_is_key_generated(const Pkcs12Ctx *this, bool *is_generated)
{
    int ret = RET_OK;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(is_generated != NULL);

    *is_generated = (this->genkey != NULL);

cleanup:

    return ret;
}

int pkcs12_generate_key(Pkcs12Ctx *this, const ByteArray *aid)
{
    int ret = RET_OK;
    AlgorithmIdentifier_t *alg_id = NULL;
    PrivateKeyInfo_t *private_key = NULL;
    Dstu4145Ctx *dstu_ctx = NULL;
    Gost28147Ctx *gost_ctx = NULL;

    CHECK_PARAM(this != NULL);

    LOG_ENTRY();

    if (aid != NULL) {
        CHECK_NOT_NULL(alg_id = asn_decode_ba_with_alloc(&AlgorithmIdentifier_desc, aid));
    } else {
        CHECK_NOT_NULL(dstu_ctx = dstu4145_alloc(DSTU4145_PARAMS_ID_M257_PB));
        CHECK_NOT_NULL(gost_ctx = gost28147_alloc(GOST28147_SBOX_ID_1));
        DO(aid_create_dstu4145(dstu_ctx, gost_ctx, true, &alg_id));
    }

    DO(pkcs8_generate(alg_id, &private_key));
    this->genkey = private_key;
    private_key = NULL;

cleanup:

    ASN_FREE(&AlgorithmIdentifier_desc, alg_id);
    ASN_FREE(&PrivateKeyInfo_desc, private_key);
    dstu4145_free(dstu_ctx);
    gost28147_free(gost_ctx);

    return ret;
}

int pkcs12_store_key(Pkcs12Ctx *this, const char *alias, const char *pwd, int rounds)
{
    int ret = RET_OK;

    CHECK_PARAM(this != NULL);

    if (this->genkey == NULL) {
        SET_ERROR(RET_STORAGE_NO_KEY);
    }

    this->owner->contents_len++;

    if (this->owner->contents == NULL) {
        this->owner->contents = pkcs12_contents_alloc(this->owner->contents_len);
    } else {
        REALLOC_CHECKED(this->owner->contents, sizeof(Pkcs12Contents *) * this->owner->contents_len, this->owner->contents);
        CALLOC_CHECKED(this->owner->contents[this->owner->contents_len - 1], sizeof(Pkcs12Contents));
    }

    DO(pkcs12_contents_set_key(alias, pwd, this->genkey, rounds, this->owner->contents[this->owner->contents_len - 1]));
    DO(pkcs12_enum_keys(this, NULL, NULL));

cleanup:

    return ret;
}

int pkcs12_set_certificates(Pkcs12Ctx *this, const ByteArray **certs)
{
    int ret = RET_OK;
    Pkcs5Params *params = NULL;
    ByteArray *iv = NULL;
    OCTET_STRING_t *octstr_iv = NULL;
    LOG_ENTRY();

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(certs != NULL);

    this->owner->contents_len++;

    if (this->owner->contents == NULL) {
        this->owner->contents = pkcs12_contents_alloc(this->owner->contents_len);
    } else {
        REALLOC_CHECKED(this->owner->contents, sizeof(Pkcs12Contents *) * this->owner->contents_len, this->owner->contents);
        CALLOC_CHECKED(this->owner->contents[this->owner->contents_len - 1], sizeof(Pkcs12Contents));
    }

    DO(pkcs12_contents_set_certs(certs, this->owner->contents[this->owner->contents_len - 1]));

    CALLOC_CHECKED(params, sizeof(Pkcs5Params));

    DO(asn_OCTSTRING2ba(&this->owner->mac_data->macSalt, &params->salt));

    if (this->owner->mac_data->iterations) {
        DO(asn_INTEGER2ulong(this->owner->mac_data->iterations, &params->iterations));
    } else {
        params->iterations = 1;
    }

    if (pkix_check_oid_equal(&this->owner->mac_data->mac.digestAlgorithm.algorithm,
            oids_get_oid_numbers_by_id(OID_PKI_GOST3411_ID))) {
        DO(aid_create_gost28147_cfb(&params->encrypt_aid));
    } else {
        CHECK_NOT_NULL(iv = ba_alloc_by_len(16));
        ASN_ALLOC(octstr_iv);

        DO(rs_std_next_bytes(iv));
        DO(asn_ba2OCTSTRING(iv, octstr_iv));

        ASN_ALLOC(params->encrypt_aid);
        DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_AES256_CBC_ID), &params->encrypt_aid->algorithm));
        DO(asn_create_any(&OCTET_STRING_desc, octstr_iv, &params->encrypt_aid->parameters));
    }

    this->owner->contents[this->owner->contents_len - 1]->params = params;
    params = NULL;

cleanup:

    if (params) {
        aid_free(params->encrypt_aid);
        ba_free(params->salt);
        free(params);
    }

    ba_free(iv);
    ASN_FREE(&OCTET_STRING_desc, octstr_iv);

    return ret;
}

int pkcs12_get_certificates(const Pkcs12Ctx *this, ByteArray ***certs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(certs != NULL);

    DO(pkcs12_contents_get_certificates((const Pkcs12Contents **)this->owner->contents, this->owner->contents_len, certs));

cleanup:

    return ret;
}

int pkcs12_get_certificate(const Pkcs12Ctx *this, int key_usage, ByteArray **cert)
{
    int ret = RET_OK;
    size_t i;

    CertStore_t *store = NULL;
    Certificate_t *asn_cert = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    ByteArray *pubkey = NULL;
    ByteArray **certs = NULL;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(cert != NULL);

    if (this->curr_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    CHECK_NOT_NULL(asn_cert = cert_alloc());
    DO(pkcs8_get_spki(this->curr_key, &spki));
    DO(spki_get_pub_key(spki, &pubkey));
    DO(pkcs12_get_certificates(this, &certs));

    i = 0;
    while (certs != NULL && certs[i] != NULL) {
        bool flag = false;

        DO(cert_decode(asn_cert, certs[i]));
        DO(cert_check_pubkey_and_usage(asn_cert, pubkey, key_usage, &flag));

        if (flag) {
            CHECK_NOT_NULL(*cert = ba_copy_with_alloc(certs[i], 0, 0));
            goto cleanup;
        }
        i++;
    }

    CHECK_NOT_NULL(store = cert_store_alloc(NULL));

    cert_free(asn_cert);
    asn_cert = NULL;

    DO(cert_store_get_certificate_by_pubkey_and_usage(store, pubkey, key_usage, &asn_cert));
    DO(cert_encode(asn_cert, cert));

cleanup:

    certs_free(certs);
    cert_free(asn_cert);
    cert_store_free(store);
    spki_free(spki);
    ba_free(pubkey);

    return ret;
}

static void keypair_free(Pkcs12Keypair *keypair)
{
    LOG_ENTRY();

    if (!keypair) {
        return;
    }

    free((char *)keypair->alias);
}

static int pkcs12_keystore_clean(Pkcs12IntStorage *storage)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(storage != NULL);

    pkcs12_contents_arr_free(storage->contents, storage->contents_len);

    free(storage->name);
    ASN_FREE(&MacData_desc, storage->mac_data);

    if (storage->password) {
        memset(storage->password, 0x00, strlen(storage->password));
        free(storage->password);
    }
    storage->contents = NULL;
    storage->name = NULL;
    storage->password = NULL;
    storage->mac_data = NULL;
    storage->state = FS_NOT_LOADED;

cleanup:

    return ret;
}

void pkcs12_free(Pkcs12Ctx *this)
{
    LOG_ENTRY();

    if (this) {
        if (this->owner) {
            pkcs12_keystore_clean(this->owner);
            free(this->owner);
        }

        pkcs8_free(this->genkey);
        pkcs8_free(this->curr_key);

        while (this->kprs_cnt--) {
            keypair_free(&this->kprs[this->kprs_cnt]);
        }

        free(this->kprs);

        free(this);
    }
}

int pkcs12_get_sign_adapter(const Pkcs12Ctx *this, SignAdapter **sa)
{
    int ret = RET_OK;
    ByteArray *cert = NULL;

    LOG_ENTRY();

    CHECK_PARAM(this);
    CHECK_PARAM(sa);

    if (this->curr_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    ret = pkcs12_get_certificate(this, 0, &cert);
    if (ret != RET_OK && ret != RET_STORAGE_CERT_NOT_FOUND) {
        SET_ERROR(ret);
    }

    DO(pkcs8_get_sign_adapter(this->curr_key, cert, sa));

cleanup:

    ba_free(cert);

    return ret;
}

int pkcs12_get_dh_adapter(const Pkcs12Ctx *this, DhAdapter **dha)
{
    int ret = RET_OK;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(dha != NULL);

    if (this->curr_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    DO(pkcs8_get_dh_adapter(this->curr_key, dha));

cleanup:

    return ret;
}

int pkcs12_get_verify_adapter(const Pkcs12Ctx *this, VerifyAdapter **va)
{
    int ret = RET_OK;


    CHECK_PARAM(this != NULL);
    CHECK_PARAM(va != NULL);

    if (this->curr_key == NULL) {
        SET_ERROR(RET_STORAGE_KEY_NOT_SELECTED);
    }

    DO(pkcs8_get_verify_adapter(this->curr_key, va));

cleanup:

    return ret;
}

static int pkcs12_set_contents(PFX_t *container, Pkcs12IntStorage *storage)
{
    int ret = RET_OK;
    size_t i;

    ByteArray *encoded = NULL;
    AuthenticatedSafe_t *objects = NULL;
    EncryptedData_t *encr_data = NULL;
    EncryptedPrivateKeyInfo_t *enc_priv_key_info = NULL;
    ContentInfo_t *authSafe = NULL;
    ContentInfo_t *cinfo = NULL;

    CHECK_PARAM(container != NULL);
    CHECK_PARAM(storage != NULL);

    ASN_ALLOC(objects);
    for (i = 0; i < storage->contents_len; i++) {
        CHECK_NOT_NULL(cinfo = cinfo_alloc());
        DO(asn_encode_ba(&SafeContents_desc, storage->contents[i]->save_contents, &encoded));

        if (storage->contents[i]->params == NULL) {
            DO(cinfo_init_by_data(cinfo, encoded));
        } else {
            ASN_ALLOC(encr_data);

            DO(asn_ulong2INTEGER(&encr_data->version, Version_v1));

            DO(pkcs5_encrypt_dstu(encoded, storage->password, storage->contents[i]->params->salt,
                    storage->contents[i]->params->iterations, storage->contents[i]->params->encrypt_aid,
                    &enc_priv_key_info));

            /* Create encryptedContentInfo. */
            EncryptedContentInfo_t *encr_content = &encr_data->encryptedContentInfo;

            DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_DATA_ID)->numbers, oids_get_oid_numbers_by_id(OID_DATA_ID)->numbers_len,
                    &encr_content->contentType));
            DO(asn_copy(&AlgorithmIdentifier_desc, &enc_priv_key_info->encryptionAlgorithm,
                    &encr_content->contentEncryptionAlgorithm));
            encr_content->encryptedContent = asn_copy_with_alloc(&OCTET_STRING_desc, &enc_priv_key_info->encryptedData);
            CHECK_NOT_NULL(encr_content->encryptedContent);

            DO(cinfo_init_by_encrypted_data(cinfo, encr_data));

            ASN_FREE(&EncryptedData_desc, encr_data);
            encr_data = NULL;
        }

        ASN_SEQUENCE_ADD(objects, cinfo);
        cinfo = NULL;

        ba_free(encoded);
        encoded = NULL;
    }

    CHECK_NOT_NULL(authSafe = cinfo_alloc());

    DO(asn_encode_ba(&AuthenticatedSafe_desc, objects, &encoded));
    DO(cinfo_init_by_data(authSafe, encoded));

    ASN_FREE_CONTENT_STATIC(&ContentInfo_desc, &container->authSafe);
    DO(asn_copy(&ContentInfo_desc, authSafe, &container->authSafe));

cleanup:

    ba_free(encoded);

    ASN_FREE(&AuthenticatedSafe_desc, objects);
    ASN_FREE(&EncryptedData_desc, encr_data);
    ASN_FREE(&EncryptedPrivateKeyInfo_desc, enc_priv_key_info);
    ASN_FREE(&ContentInfo_desc, authSafe);
    ASN_FREE(&ContentInfo_desc, cinfo);

    return ret;
}

int pkcs12_encode(const Pkcs12Ctx *this, ByteArray **storage_body)
{
    int ret = RET_OK;
    PFX_t *pfx_container = NULL;
    INTEGER_t *version3 = NULL;

    CHECK_PARAM(this != NULL);
    CHECK_PARAM(storage_body != NULL);

    Pkcs12IntStorage *storage = this->owner;

    ASN_ALLOC(pfx_container);

    DO(asn_create_integer_from_long(3, &version3));
    DO(asn_copy(&INTEGER_desc, version3, &pfx_container->version));
    DO(pkcs12_set_contents(pfx_container, storage));

    CHECK_NOT_NULL(pfx_container->macData = asn_copy_with_alloc(&MacData_desc, storage->mac_data));

    if (storage->state != FS_ACTUAL_STATE) {
        DO(pfx_update_mac_data(pfx_container, storage->password));
    }

    DO(pfx_encode(pfx_container, storage_body));

cleanup:

    ASN_FREE(&PFX_desc, pfx_container);
    ASN_FREE(&INTEGER_desc, version3);

    return ret;
}

/**
 * Возвращает инициализированный контекст хранилища.
 *
 * @param id тип
 * @param storage контекст хранилища PKCS #12
 *
 * @return контекст хранилища
 */
static Pkcs12Ctx *get_storage_pkcs12(Pkcs12IntStorage *storage)
{
    Pkcs12Ctx *storage_pkcs12 = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(storage != NULL);

    CALLOC_CHECKED(storage_pkcs12, sizeof(Pkcs12Ctx));

    storage_pkcs12->owner = storage;
    storage_pkcs12->kprs = NULL;
    storage_pkcs12->kprs_cnt = 0;
    storage_pkcs12->genkey = NULL;
    storage_pkcs12->curr_key = NULL;

cleanup:

    return storage_pkcs12;
}

/**
 * Выполняет освобождение памяти, занимаемой хранилищем.
 */
static void pkcs12_int_free(Pkcs12IntStorage *storage)
{
    LOG_ENTRY();

    if (storage) {
        pkcs12_keystore_clean(storage);
        free(storage);
    }
}

static Pkcs12IntStorage *pkcs12_keystore_alloc(void)
{
    Pkcs12IntStorage *storage = NULL;

    LOG_ENTRY();
    if ((storage = calloc(1, sizeof(Pkcs12IntStorage))) == NULL) {
        ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
        return NULL;
    }

    return storage;
}

int pkcs12_create(Pkcs12MacType id, const char *password, int rounds, Pkcs12Ctx **storage)
{
    int ret = RET_OK;
    Pkcs12IntStorage *int_storage = NULL;

    CHECK_PARAM(storage != NULL);
    CHECK_PARAM(password != NULL);

    CHECK_NOT_NULL(int_storage = pkcs12_keystore_alloc());
    CHECK_NOT_NULL(int_storage->password = dupstr(password));
    int_storage->state = FS_MODIFIED_STATE;
    DO(pkcs12_create_empty_mac_data(id, rounds, &int_storage->mac_data));

    CHECK_NOT_NULL(*storage = get_storage_pkcs12(int_storage));
    int_storage = NULL;

cleanup:

    pkcs12_int_free(int_storage);

    return ret;
}

int pkcs12_decode(const char *storage_name, const ByteArray *storage_body, const char *pass, Pkcs12Ctx **storage)
{
    int ret = RET_OK;
    Pkcs12IntStorage *int_storage = NULL;
    PFX_t *pfx = NULL;

    LOG_ENTRY();

    CHECK_PARAM(storage_body != NULL);
    CHECK_PARAM(pass != NULL);
    CHECK_PARAM(storage != NULL);

    CHECK_NOT_NULL(int_storage = pkcs12_keystore_alloc());

    if (storage_name != NULL) {
        CHECK_NOT_NULL(int_storage->name = dupstr(storage_name));
    } else {
        int_storage->name = NULL;
    }
    CHECK_NOT_NULL(int_storage->password = dupstr(pass));

    CHECK_NOT_NULL(pfx = pfx_alloc());
    DO(pfx_decode(pfx, storage_body));

    if (pfx->macData != NULL) {
        DO(pfx_check_mac(pfx, pass));
    }

    DO(pfx_get_contents(pfx, pass, &int_storage->contents, &int_storage->contents_len));
    CHECK_NOT_NULL(int_storage->mac_data = asn_copy_with_alloc(&MacData_desc, pfx->macData));

    int_storage->state = FS_ACTUAL_STATE;

    *storage = get_storage_pkcs12(int_storage);

    int_storage = NULL;

cleanup:

    pkcs12_int_free(int_storage);
    pfx_free(pfx);

    return ret;
}
