/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "cert_store.h"

#include <string.h>

#include "asn1_utils.h"
#include "pkix_utils.h"
#include "cert.h"
#include "storage_errors.h"
#include "pkix_macros_internal.h"
#include "dirent_internal.h"
#include "pthread_internal.h"
#include "log_internal.h"

#define DEFAULT_CERT_PATH   "./"
#define CERT_EXT            ".cer"

#undef FILE_MARKER
#define FILE_MARKER "storage/cert_store.c"

/** Структура хранилища сертификатов. */
struct CertStore_st {
    char *path;          /**< путь к хранилищу */
    const void *ctx;
};

static pthread_mutex_t cert_store_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *cert_store_default_path = NULL;

int cert_store_set_default_path(const char *path)
{
    int ret = RET_OK;

    pthread_mutex_lock(&cert_store_mutex);

    cert_store_default_path = (path != NULL) ? dupstr(path) : NULL;

    pthread_mutex_unlock(&cert_store_mutex);

    return ret;
}

CertStore_t *cert_store_alloc(const char *path)
{
    CertStore_t *store = NULL;
    int ret = RET_OK;

    pthread_mutex_lock(&cert_store_mutex);

    CALLOC_CHECKED(store, sizeof(CertStore_t));
    store->ctx = NULL;

    if (path == NULL) {
        CHECK_NOT_NULL(store->path = dupstr(DEFAULT_CERT_PATH));
    } else {
        CHECK_NOT_NULL(store->path = dupstr(path));
    }

cleanup:

    pthread_mutex_unlock(&cert_store_mutex);

    if (ret != RET_OK) {
        cert_store_free(store);
        store = NULL;
    }

    return store;
}

void cert_store_free(CertStore_t *store)
{
    if (store) {
        pthread_mutex_lock(&cert_store_mutex);
        free(store->path);
        free(store);
        pthread_mutex_unlock(&cert_store_mutex);
    }
}

int cert_store_add_certificate(CertStore_t *store, const char *alias, const Certificate_t *cert)
{
    ByteArray *sn = NULL;
    ByteArray *encoded = NULL;
    char *cert_path = NULL;
    const uint8_t *buf;
    int ret = RET_OK;
    size_t i;

    CHECK_PARAM(store != NULL);
    CHECK_PARAM(alias != NULL);
    CHECK_PARAM(cert != NULL);

    DO(cert_get_sn(cert, &sn));

    CALLOC_CHECKED(cert_path, strlen(store->path) + strlen(alias) + ba_get_len(sn) * 2 + strlen(CERT_EXT) + 1);
    strcpy(cert_path, store->path);
    strcat(cert_path, alias);

    buf = ba_get_buf(sn);

    for (i = 0; i < ba_get_len(sn); i++) {
        sprintf(cert_path + strlen(cert_path), "%02x", buf[i] & 0xff);
    }

    strcat(cert_path, CERT_EXT);

    DO(cert_encode(cert, &encoded));
    DO(ba_to_file(encoded, cert_path));

cleanup:

    ba_free(encoded);
    ba_free(sn);
    free(cert_path);

    return ret;
}

int cert_store_add_certificates(CertStore_t *store, const char *prefix, const Certificates_t *certs)
{
    int ret = RET_OK;
    int i;

    CHECK_PARAM(store != NULL);
    CHECK_PARAM(prefix != NULL);
    CHECK_PARAM(certs != NULL);

    for (i = 0; i < certs->list.count; i++) {
        DO(cert_store_add_certificate(store, prefix, certs->list.array[i]));
    }

cleanup:

    return ret;
}

int cert_store_get_certificates_by_alias(CertStore_t *store, const char *alias_prefix, Certificates_t **asn_certs)
{
    int ret = RET_OK;

    char *cert_path = NULL;
    DIR *dir;
    struct dirent *in_file;
    ByteArray *encoded = NULL;
    Certificate_t *cert = NULL;
    Certificates_t *certs = NULL;

    CHECK_PARAM(store != NULL);
    CHECK_PARAM(asn_certs != NULL);

    dir = opendir(store->path);
    if (!dir) {
        SET_ERROR(RET_DIR_OPEN_ERROR);
    }

    ASN_ALLOC(certs);

    while ((in_file = readdir(dir))) {
        if (is_dir(in_file->d_name)) {
            continue;
        }

        if (!strcmp(in_file->d_name, ".") || !strcmp (in_file->d_name, "..")) {
            continue;
        }

        if (alias_prefix != NULL && (strlen(in_file->d_name) < strlen(alias_prefix)
                || memcmp(in_file->d_name, alias_prefix, strlen(alias_prefix)))) {
            continue;
        }

        MALLOC_CHECKED(cert_path, strlen(store->path) + strlen(in_file->d_name) + 1);
        strcpy(cert_path, store->path);
        strcat(cert_path, in_file->d_name);

        ret = ba_alloc_from_file(cert_path, &encoded);
        free(cert_path);
        cert_path = NULL;

        /* Игнорируем файл, если не смогли его прочитать. */
        if (ret != RET_OK) {
            continue;
        }

        CHECK_NOT_NULL(cert = cert_alloc());
        ret = cert_decode(cert, encoded);

        ba_free(encoded);
        encoded = NULL;

        if (ret != RET_OK) {
            cert_free(cert);
            cert = NULL;
            continue;
        }

        ASN_SEQUENCE_ADD(&certs->list, cert);
        cert = NULL;
    }

    ret = RET_OK;

    *asn_certs = certs;
    certs = NULL;

    closedir(dir);

cleanup:

    ba_free(encoded);
    cert_free(cert);
    free(cert_path);
    ASN_FREE(&Certificates_desc, certs);

    return ret;
}

int cert_store_get_certificate_by_pubkey_and_usage(CertStore_t *store, const ByteArray *pubkey, int keyusage,
        Certificate_t **cert)
{
    int ret = RET_OK;
    int i;
    Certificates_t *certs = NULL;

    LOG_ENTRY();

    CHECK_PARAM(pubkey != NULL);
    CHECK_PARAM(store != NULL);
    CHECK_PARAM(cert != NULL);

    DO(cert_store_get_certificates_by_alias(store, NULL, &certs));

    for (i = 0; i < certs->list.count; i++) {
        bool flag = false;
        ret = cert_check_pubkey_and_usage(certs->list.array[i], pubkey, keyusage, &flag);

        if ((ret == RET_OK) && flag) {
            CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&Certificate_desc, certs->list.array[i]));
            goto cleanup;
        }
    }

    SET_ERROR(RET_STORAGE_CERT_NOT_FOUND);

cleanup:

    ASN_FREE(&Certificates_desc, certs);

    return ret;
}
