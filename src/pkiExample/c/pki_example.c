/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>

#include <errno.h>
#include <sys/stat.h>

#if defined(_WIN32)
#include <windows.h>
#undef S_IRWXU
#undef S_IRWXG
#undef S_IROTH
#undef S_IXOTH
#undef EEXIST
#define S_IRWXU 0
#define S_IRWXG 0
#define S_IROTH 0
#define S_IXOTH 0
#define EEXIST ERROR_ALREADY_EXISTS
#endif

#define REPORT_DIR "build/tmp/pkiExample"

/* Криптопровайдер. */

#include "stacktrace.h"

/* PKIX. */
#include "pkix_utils.h"
#include "oids.h"
#include "rs.h"

/* Движки PKI. */
#include "crypto_cache.h"
#include "cert_engine.h"
#include "certificate_request_engine.h"
#include "signer_info_engine.h"
#include "signed_data_engine.h"
#include "crl_engine.h"
#include "tsp_request_engine.h"
#include "ocsp_request_engine.h"
#include "ocsp_response_engine.h"
#include "enveloped_data_engine.h"
#include "tsp_response_engine.h"
#include "ext.h"
#include "exts.h"

#include "pkix_errors.h"

#include "cryptonite_manager.h"
#include "certification_request.h"
#include "cert.h"
#include "aid.h"
#include "spki.h"
#include "content_info.h"
#include "signed_data.h"
#include "asn1_utils.h"
#include "ocsp_response.h"
#include "ocsp_request.h"
#include "crl.h"
#include "signer_info.h"
#include "tsp_response.h"
#include "tsp_request.h"
#include "enveloped_data.h"
#include "pkcs12.h"


/* -------------------- Обработка ошибок ------------------- */

#define EXECUTE(func)                                                    \
    {                                                                    \
        int _error_code = (func);                                        \
                                                                         \
        if (_error_code != RET_OK) { \
            tprintf("%s:%i: Execute failed, return = 0x%x\n",            \
                    __FILE__,__LINE__, _error_code);                     \
            error_count++;                                               \
            ERROR_ADD(_error_code);                                      \
            error_print(stacktrace_get_last());                          \
            return;                                                      \
        }                                                                \
    }

#define IS_NULL(p)                                          \
    {                                                       \
        if ((p) == NULL) {                                  \
            tprintf("%i: Execute failed, return = NULL\n",  \
                    __LINE__);                              \
            error_count++;                                  \
            return;                                         \
        }                                                   \
    }

#define GET_ARR_CNT(x) (sizeof(x) / sizeof(x[0]))

/* -------------------- Счетчик ошибок --------------------- */

static int error_count = 0;

/* ---------- Тестовые криптографические параметры --------- */

#define PRNG_SEED_SIZE 128
#define SERIAL_LEN 20

#define DEFAULT_STORAGE_PASSWORD "123456"
#define DEFAULT_KEY_PASSWORD     "123456"
#define PASSWORD_HASH_ROUNDS              1024

#define FULL_CRL_SN "0123"
#define DELTA_CRL_SN "0124"

static Dstu4145Ctx *dstu_params[15] = {0};
static Gost28147Ctx *cipher_params = NULL;

Gost28147SboxId sbox_params_id = GOST28147_SBOX_ID_1;

static Dstu4145ParamsId dstu_params_id_map[] = {
    DSTU4145_PARAMS_ID_M163_PB,
    DSTU4145_PARAMS_ID_M167_PB,
    DSTU4145_PARAMS_ID_M173_PB,
    DSTU4145_PARAMS_ID_M179_PB,
    DSTU4145_PARAMS_ID_M191_PB,
    DSTU4145_PARAMS_ID_M233_PB,
    DSTU4145_PARAMS_ID_M257_PB,
    DSTU4145_PARAMS_ID_M307_PB,
    DSTU4145_PARAMS_ID_M367_PB,
    DSTU4145_PARAMS_ID_M431_PB,
    DSTU4145_PARAMS_ID_M173_ONB,
    DSTU4145_PARAMS_ID_M179_ONB,
    DSTU4145_PARAMS_ID_M191_ONB,
    DSTU4145_PARAMS_ID_M233_ONB,
    DSTU4145_PARAMS_ID_M431_ONB
};

static const char *dstu_params_name_map[] = {
    "DSTU4145_M163_PB",
    "DSTU4145_M167_PB",
    "DSTU4145_M173_PB",
    "DSTU4145_M179_PB",
    "DSTU4145_M191_PB",
    "DSTU4145_M233_PB",
    "DSTU4145_M257_PB",
    "DSTU4145_M307_PB",
    "DSTU4145_M367_PB",
    "DSTU4145_M431_PB",
    "DSTU4145_M173_ONB",
    "DSTU4145_M179_ONB",
    "DSTU4145_M191_ONB",
    "DSTU4145_M233_ONB",
    "DSTU4145_M431_ONB"
};

void error_print(const ErrorCtx *ctx)
{
    const ErrorCtx *step = NULL;
    const char arr[] = "--------------------------------------------------------------------------------";
    printf("%s\n", arr);
    printf("| Stacktrace:\n");
    if (ctx) {
        step = ctx;
        do {
            printf("|%s:%u, ERROR: %i\n",
                    step->file,
                    (unsigned int)step->line,
                    step->error_code);
            step = step->next;
        } while (step != NULL);
    }
    printf("%s\n", arr);
}

static int dstu_params_count = sizeof(dstu_params_id_map) / sizeof(Dstu4145ParamsId);

/* --------------------- Ввод / вывод ---------------------- */

static int tprintf(const char *fmt, ...)
{
    va_list argp;
    int ret;

    va_start(argp, fmt);
    ret = vprintf(fmt, argp);
    va_end(argp);
    fflush(stdout);

    return ret;
}

/** Converts from POSIX to target platform style path. */
static void rp_path(char *path)
{
#if defined(_WIN32)
    char *p = path;

    while (*p != '\0') {
        if (*p == '/') {
            *p = '\\';
        }
        p++;
    }
#else
    (void)path;
#endif
}

/** Makes a directory. */
static int rp_mkdir(const char *path, int mode)
{
#if defined(_WIN32)
    (void)mode;
    SetLastError(0);
    if (CreateDirectory(path, NULL)) {
        errno = 0;
        return 0;
    } else {
        errno = GetLastError();
        return -1;
    }
#else
    return mkdir(path, mode);
#endif
}

/** Create directory. */
static bool mkpath(char *path, int mode)
{
    char *p = path;

    while (*p != '\0') {
        char v;
        p++;

        /* Find first slash or end. */
#if defined(_WIN32)
        while (*p != '\0' && *p != '\\') {
            p++;
        }
#else
        while (*p != '\0' && *p != '/') {
            p++;
        }
#endif

        if (*p == '\0') {
            return true;
        }

        /* Create folder from path to '\0' inserted at p. */
        v = *p;
        *p = '\0';
        if (rp_mkdir(path, mode) == -1 && errno != EEXIST) {
            *p = v;
            error_count++;
            return false;
        }
        *p = v;
    }

    return true;
}

static void save_ba_to_file(const ByteArray *ba, const char *params_name, const char *file)
{
    int ret = RET_OK;
    const char *root_path = REPORT_DIR;
    char *path = calloc(1, strlen(file) + strlen(root_path) + strlen(params_name) + 3);

    strcpy(path, root_path);
    strcat(path, "/");
    strcat(path, params_name);
    strcat(path, "/");
    strcat(path, file);

    rp_path(path);

    if (!mkpath(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
        printf("Making path error (%s).\n", path);
        error_count++;
        goto cleanup;
    }

    ret = ba_to_file(ba, path);
    if (ret == RET_FILE_OPEN_ERROR) {
        printf("File open error (%s).\n", path);
        error_count++;
    } else if (ret == RET_FILE_WRITE_ERROR) {
        printf("File writing error (%s).\n", path);
        error_count++;
    }

cleanup:

    free(path);
}

/**
 * Чтение байтов из файла в буфер.
 *
 * @param buffer      буфер
 * @param buffer_size размер буфера
 * @param params_name название параметров
 * @param file        название файла
 */
static void load_ba_from_file(ByteArray **buffer_ba, const char *params_name, const char *file)
{
    const char *root_path = REPORT_DIR;
    char *path = calloc(1, strlen(file) + strlen(root_path) + strlen(params_name) + 3);
    int ret = RET_OK;

    strcpy(path, root_path);
    strcat(path, "/");
    strcat(path, params_name);
    strcat(path, "/");
    strcat(path, file);

    rp_path(path);

    ret = ba_alloc_from_file(path, buffer_ba);
    if (ret != RET_OK) {
        if (ret == RET_FILE_OPEN_ERROR) {
            printf("File open error (%s).\n", path);
        } else {
            printf("File reading error (%s).\n", path);
        }
    }

    free(path);
}

void expr_true(bool e, const char *file, int line)
{
    if (!e) {
        tprintf("%s:%i: Assert failed.\n", file, line);
        error_count++;
    }
}

#define assert_true(expression)                 \
    expr_true(expression, __FILE__, __LINE__)

static void extgen_deltacrl(const ByteArray *crl_number,
        const Certificate_t *issuer,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;
    ByteArray *sn = ba_alloc_from_le_hex_string(DELTA_CRL_SN);

    exts = exts_alloc();

    EXECUTE(ext_create_crl_number(false, sn, &ext));
    ba_free(sn);
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_delta_crl_indicator(true, crl_number, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;
}

static void extgen_fullcrl(const Certificate_t *issuer, Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;
    ByteArray *full_crl_sn = ba_alloc_from_le_hex_string(FULL_CRL_SN);

    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    exts = exts_alloc();

    EXECUTE(ext_create_crl_number(false, full_crl_sn, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;
    ba_free(full_crl_sn);
}

static void extgen_ocsp(const SubjectPublicKeyInfo_t *spki,
        const DigestAdapter *digest,
        const Validity_t *validity,
        const Certificate_t *issuer_cert,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;
    (void)digest;

    OBJECT_IDENTIFIER_t *extkey_usage = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};

    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    EXECUTE(asn_create_oid_from_text("1.3.6.1.5.5.7.3.9", &extkey_usage));

    exts = exts_alloc();

    EXECUTE(ext_create_subj_key_id(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer_cert, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_private_key_usage(false, validity, NULL, NULL, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_key_usage(true, KEY_USAGE_DIGITAL_SIGNATURE, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_ext_key_usage(true, &extkey_usage, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_basic_constraints(true, NULL, false, 0, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_qc_statement_compliance(&qc_statement));
    EXECUTE(ext_create_qc_statements(true, &qc_statement, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_crl_distr_points(false, crl_distr, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;

    ASN_FREE(get_OBJECT_IDENTIFIER_desc(), extkey_usage);
    ASN_FREE(get_QCStatement_desc(), qc_statement);
}

static void extgen_root(const SubjectPublicKeyInfo_t *spki,
        const CertificationRequest_t *request,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;
    DigestAdapter *da = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};
    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    long auth_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 1};
    OidNumbers auth_info1 = {auth_info_oid, 9};
    OidNumbers *auth_info = &auth_info1;
    const char *auth_uri[] = {"http://ca.ua/ocsp/"};

    exts = exts_alloc();

    EXECUTE(digest_adapter_init_by_aid(&spki->algorithm, &da));

    EXECUTE(ext_create_subj_key_id(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_spki(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_key_usage(true, KEY_USAGE_KEY_CERTSIGN | KEY_USAGE_CRL_SIGN, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_basic_constraints(true, NULL, true, 0, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(creq_get_ext_by_oid(request, oids_get_oid_numbers_by_id(OID_SUBJECT_ALT_NAME_EXTENSION_ID), &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_qc_statement_compliance(&qc_statement));
    EXECUTE(ext_create_qc_statements(false, &qc_statement, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_crl_distr_points(true, crl_distr, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_info_access(false, &auth_info, auth_uri, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;

    digest_adapter_free(da);
    ASN_FREE(get_QCStatement_desc(), qc_statement);
}

static void extgen_tsp(const SubjectPublicKeyInfo_t *spki,
        const DigestAdapter *digest,
        const Validity_t *validity,
        const Certificate_t *issuer_cert,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;

    OBJECT_IDENTIFIER_t *extkey_usage = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};

    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    long auth_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 1};
    OidNumbers auth_info1 = {auth_info_oid, 9};
    OidNumbers *auth_info = &auth_info1;
    const char *auth_uri[] = {"http://ca.ua/ocsp/"};

    EXECUTE(asn_create_oid_from_text("1.3.6.1.5.5.7.3.8", &extkey_usage));

    (void)digest;
    exts = exts_alloc();

    EXECUTE(ext_create_subj_key_id(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer_cert, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_private_key_usage(false, validity, NULL, NULL, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_key_usage(true, KEY_USAGE_DIGITAL_SIGNATURE, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_ext_key_usage(true, &extkey_usage, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_basic_constraints(true, NULL, false, 0, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_qc_statement_compliance(&qc_statement));
    EXECUTE(ext_create_qc_statements(true, &qc_statement, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_crl_distr_points(false, crl_distr, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_info_access(false, &auth_info, auth_uri, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;

    ASN_FREE(get_OBJECT_IDENTIFIER_desc(), extkey_usage);
    ASN_FREE(get_QCStatement_desc(), qc_statement);
}

static void extgen_userfiz(const SubjectPublicKeyInfo_t *spki,
        const Certificate_t *issuer_cert,
        const CertificationRequest_t *cert_request,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};
    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    exts = exts_alloc();

    EXECUTE(ext_create_subj_key_id(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    /* Проверить что это ext_auth_key_id, копируется ли структура? */
    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer_cert, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_key_usage(true, KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_ENCIPHERMENT | KEY_USAGE_KEY_AGREEMENT,
            &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_basic_constraints(true, NULL, false, 0, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_qc_statement_compliance(&qc_statement));
    EXECUTE(ext_create_qc_statements(true, &qc_statement, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_crl_distr_points(false, crl_distr, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(creq_get_ext_by_oid(cert_request, oids_get_oid_numbers_by_id(OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID),
            &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;

    ASN_FREE(get_QCStatement_desc(), qc_statement);
}

static void extgen_userur(const Certificate_t *issuer_cert,
        const SubjectPublicKeyInfo_t *spki,
        const DigestAdapter *digest,
        const CertificationRequest_t *request,
        Extensions_t **extensions)
{
    Extensions_t *exts = NULL;
    Extension_t *ext = NULL;
    DigestAlgorithmIdentifier_t *daid = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};

    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};

    exts = exts_alloc();
    EXECUTE(digest->get_alg(digest, &daid));
    EXECUTE(ext_create_subj_key_id(false, spki, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ASN_FREE(get_DigestAlgorithmIdentifier_desc(), daid);
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_auth_key_id_from_cert(false, issuer_cert, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_key_usage(true, KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_ENCIPHERMENT | KEY_USAGE_KEY_AGREEMENT,
            &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_basic_constraints(true, NULL, false, 0, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    QCStatement_t **qc_statements = malloc(2 * sizeof(QCStatement_t *));
    EXECUTE(ext_create_qc_statement_compliance(&qc_statement));
    qc_statements[0] = qc_statement;
    EXECUTE(ext_create_qc_statement_limit_value("UAH", 1000, 0, &qc_statement));
    qc_statements[1] = qc_statement;

    EXECUTE(ext_create_qc_statements(true, qc_statements, 2, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_crl_distr_points(false, crl_distr, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    EXECUTE(creq_get_ext_by_oid(request, oids_get_oid_numbers_by_id(OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID), &ext));
    EXECUTE(exts_add_extension(exts, ext));
    ext_free(ext);
    ext = NULL;

    *extensions = exts;

    ASN_FREE(get_QCStatement_desc(), qc_statements[0]);
    ASN_FREE(get_QCStatement_desc(), qc_statements[1]);
    free(qc_statements);
}

/* -------------------- Генерация ключей ДСТУ 4145-2002 ------------------- */

/**
 * Генерация ключей ДСТУ 4145-2002.
 *
 * @param ec_params параметры ДСТУ 4145 из Testа
 * @param cipher_params параметры ГОСТ 28147 из Testа
 * @param aid идентификатор криптографического алгоритма
 * @param key закрытый ключ
 * @param spki информация об открытом ключе
 */
static void generate_dstu_keypair(Dstu4145Ctx *ec_params, Gost28147Ctx *cipher_params, Pkcs12Ctx **key)
{
    Pkcs12Ctx *storage = NULL;
    ByteArray *aid_ba = NULL;
    AlgorithmIdentifier_t *aid = NULL;

    /* Формируем идентификатор криптографического алгоритма. */
    bool is_le = true;

    EXECUTE(aid_create_dstu4145(ec_params, cipher_params, is_le, &aid));
    EXECUTE(aid_encode(aid, &aid_ba));
    EXECUTE(pkcs12_create(KS_FILE_PKCS12_WITH_GOST34311, DEFAULT_STORAGE_PASSWORD, PASSWORD_HASH_ROUNDS, &storage));
    EXECUTE(pkcs12_generate_key(storage, aid_ba));
    EXECUTE(pkcs12_store_key(storage, "alias", DEFAULT_KEY_PASSWORD, PASSWORD_HASH_ROUNDS));
    EXECUTE(pkcs12_select_key(storage, "alias", DEFAULT_KEY_PASSWORD));

    *key = storage;

    ba_free(aid_ba);
    aid_free(aid);
}

static void dstu4145_cache_init_all_std_params(void)
{
    EXECUTE(crypto_cache_add_any_new(OPT_LEVEL_COMB_5_WIN_5));
}

static void dstu4145_init_all_std_params(void)
{
    size_t i;

    for (i = 0; i < sizeof(dstu_params_id_map) / sizeof(Dstu4145ParamsId); i++) {
        dstu_params[i] = dstu4145_alloc(dstu_params_id_map[i]);
        IS_NULL(dstu_params[i]);
    }
}

static void gost3411_init_std_params(void)
{
    cipher_params = gost28147_alloc(sbox_params_id);
    IS_NULL(cipher_params);
}

static void dstu4145_free_all_std_params(void)
{
    size_t i;

    for (i = 0; i < sizeof(dstu_params_id_map) / sizeof(Dstu4145ParamsId); i++) {
        dstu4145_free(dstu_params[i]);
        dstu_params[i] = NULL;
    }
}

static void gost3411_free_std_params(void)
{
    gost28147_free(cipher_params);
    cipher_params = NULL;
}

static void generate_root_certificate_core(const char *dstu_params_name,
        Pkcs12Ctx *storage,
        const char *subject,
        const time_t *not_before,
        const time_t *not_after,
        const unsigned char *serial,
        const Extensions_t *extensions,
        const CertificationRequest_t *cert_request,
        const SignAdapter *sa,
        const char *req_path,
        const char *cert_path,
        const char *pr_key_path)
{
    ByteArray *encoded = NULL;
    ByteArray *storage_body = NULL;
    Certificate_t *root_cert = NULL;
    DigestAdapter *da = NULL;
    VerifyAdapter *va = NULL;
    ByteArray *serial_ba = ba_alloc_from_uint8(serial, 20);
    SubjectPublicKeyInfo_t *spki = NULL;

    CertificateEngine *cert_engine_ctx = NULL;

    (void)subject;

    EXECUTE(pkcs12_get_verify_adapter(storage, &va));
    EXECUTE(va->get_pub_key(va, &spki));
    EXECUTE(digest_adapter_init_by_aid(&spki->algorithm, &da));

    /* Запись результата. */
    EXECUTE(creq_encode(cert_request, &encoded));

    save_ba_to_file(encoded, dstu_params_name, req_path);
    ba_free(encoded);
    encoded = NULL;

    /* Инициализация генератора сертификатов. */
    EXECUTE(ecert_alloc(sa, da, true, &cert_engine_ctx));

    /* Генерация сертификата по запросу на сертификат и серийному номеру. */
    EXECUTE(ecert_generate(cert_engine_ctx, cert_request, 2, serial_ba, not_before, not_after, extensions, &root_cert));

    /* Проверка подписи под самоподписанным сертификатом. */
    EXECUTE(cert_verify(root_cert, va));

    /* Запись результата. */
    EXECUTE(cert_encode(root_cert, &encoded));


    save_ba_to_file(encoded, dstu_params_name, cert_path);

    const ByteArray *certs[2] = {NULL, NULL};
    certs[0] = encoded;
    certs[1] = NULL;
    EXECUTE(pkcs12_set_certificates(storage, certs));

    EXECUTE(pkcs12_encode(storage, &storage_body));
    save_ba_to_file(storage_body, dstu_params_name, pr_key_path);
    ba_free(encoded);
    encoded = NULL;

    cert_free(root_cert);
    ecert_free(cert_engine_ctx);

    verify_adapter_free(va);
    digest_adapter_free(da);
    ba_free(serial_ba);
    ba_free(storage_body);

    spki_free(spki);
}

static void generate_cert_core(const CertificationRequest_t *cert_request,
        const time_t *not_before,
        const time_t *not_after,
        const unsigned char *serial,
        const Extensions_t *extensions,
        const ByteArray *issuer_storage_body,
        const Certificate_t *issuer_cert,
        Certificate_t **new_cert)
{
    VerifyAdapter *va = NULL;
    DigestAdapter *da = NULL;
    SignAdapter   *sa = NULL;
    ByteArray *serial_ba = ba_alloc_from_uint8(serial, 20);
    Pkcs12Ctx *storage = NULL;

    CertificateEngine *cert_engine_ctx = NULL;

    /*
     * Настройка контекста для формирования подписи под запросом на
     * сертификат и под самоподписанным сертификатом.
     */

    EXECUTE(digest_adapter_init_by_aid(&cert_request->certificationRequestInfo.subjectPKInfo.algorithm, &da));
    EXECUTE(verify_adapter_init_by_cert(issuer_cert, &va));
    EXECUTE(pkcs12_decode(NULL, issuer_storage_body, DEFAULT_STORAGE_PASSWORD, &storage));
    EXECUTE(pkcs12_select_key(storage, NULL, DEFAULT_KEY_PASSWORD));
    EXECUTE(pkcs12_get_sign_adapter(storage, &sa));
    EXECUTE(sa->set_cert(sa, issuer_cert));

    /* Инициализация генератора сертификатов. */
    EXECUTE(ecert_alloc(sa, da, false, &cert_engine_ctx));

    /* Генерация сертификата по запросу на сертификат и серийному номеру. */
    EXECUTE(ecert_generate(cert_engine_ctx, cert_request, 2, serial_ba, not_before, not_after, extensions, new_cert));

    /* Проверка подписи под сертификатом. */
    EXECUTE(cert_verify(*new_cert, va));

    ecert_free(cert_engine_ctx);

    verify_adapter_free(va);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    ba_free(serial_ba);
    pkcs12_free(storage);
}

/** Генерация корневого сертификата. */
void generate_root_certificate(void)
{
    int i;
    time_t not_before;
    time_t not_after;
    struct tm *timeinfo = NULL;

    Pkcs12Ctx *storage = NULL;
    CertificationRequest_t *cert_request = NULL;
    Extensions_t *extensions = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    SignAdapter   *sa = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    char dns[] = "ca.ua";
    char email[] = "info@ca.ua";
    char *res_folder = NULL;

    /* Серийный номер сертификата. */
    const unsigned char root_serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00
    };

    /* Информация о получателе сертификата. */
    const char subject[] =
            "{O=ТЕСТ}"
            "{OU=ЦСК}"
            "{CN=ЦСК ТЕСТ}"
            "{SN=UA-123456789-4312}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}";

    /* UTC time 26.01.23 22:00:00. */
    timeinfo = calloc(1, sizeof(struct tm));
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 26.01.13 22:00:00. */
    timeinfo = calloc(1, sizeof(struct tm));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        tprintf("        - Генерация корневой ключевой пары (%s).\n", res_folder);
        generate_dstu_keypair(dstu_params[i], cipher_params, &storage);
        IS_NULL(storage);


        EXECUTE(pkcs12_get_sign_adapter(storage, &sa));
        EXECUTE(sa->get_pub_key(sa, &spki));

        tprintf("        - Генерация запроса на сертификат (%s).\n", res_folder);
        EXECUTE(ecert_request_alloc(sa, &cert_request_eng));
        EXECUTE(ecert_request_set_subj_name(cert_request_eng, subject));
        EXECUTE(ecert_request_set_subj_alt_name(cert_request_eng, dns, email));
        EXECUTE(ecert_request_generate(cert_request_eng, &cert_request));

        extgen_root(spki, cert_request, &extensions);
        IS_NULL(extensions);

        tprintf("        - Создание корневого сертификата (%s).\n", res_folder);
        generate_root_certificate_core(res_folder, storage, subject, &not_before, &not_after, root_serial,
                extensions, cert_request, sa, "root/request.csr", "root/certificate.cer", "root/private.key");

        pkcs12_free(storage);
        storage = NULL;

        creq_free(cert_request);
        cert_request = NULL;

        exts_free(extensions);
        extensions = NULL;
        spki_free(spki);
        spki = NULL;
        ecert_request_free(cert_request_eng);
        cert_request_eng = NULL;

        sign_adapter_free(sa);
        sa = NULL;
    }
}

static void load_certificate(const char *params_name, const char *file, Certificate_t **cert)
{
    ByteArray *encoded = NULL;

    load_ba_from_file(&encoded, params_name, file);

    *cert = cert_alloc();
    EXECUTE(cert_decode(*cert, encoded));

    ba_free(encoded);
}

/**
 * Генерирует примеры сертификатов для физических лиц.
 */
void generate_user_fiz_certificate(void)
{
    int i;
    time_t not_before;
    time_t not_after;
    struct tm *timeinfo = NULL;

    ByteArray *encoded = NULL;

    ByteArray *issuer_key_body = NULL;
    ByteArray *subject_storage_body = NULL;
    Pkcs12Ctx *subject_storage = NULL;

    Certificate_t *issuer_cert = NULL;
    Certificate_t *subject_cert = NULL;
    CertificationRequest_t *subject_cert_request = NULL;

    Extensions_t *extensions = NULL;
    SubjectPublicKeyInfo_t *subject_spki = NULL;

    SignAdapter   *subject_sa = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    char subject_attr[] = "{1.2.804.2.1.1.1.11.1.4.1.1=292431128}";

    /* Серийный номер сертификата. */
    const unsigned char serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x02
    };

    char *res_folder;

    /* Информация о получателе сертификата. */
    const char subject[] =
            "{O=Петров Василь Олександрович ФОП}"
            "{OU=Керiвництво}"
            "{CN=Петров В.О.}"
            "{SRN=Петров}"
            "{GN=Василь Олександрович}"
            "{SN=9834567812}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}"
            "{T=Підприємець}";

    /* UTC time 25.01.23 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {

        res_folder = (char *)dstu_params_name_map[i];

        tprintf("        - Генерация ключевой пары (%s).\n", res_folder);

        generate_dstu_keypair(dstu_params[i], cipher_params, &subject_storage);
        IS_NULL(subject_storage);

        EXECUTE(pkcs12_get_sign_adapter(subject_storage, &subject_sa));
        EXECUTE(subject_sa->get_pub_key(subject_sa, &subject_spki));
        EXECUTE(ecert_request_alloc(subject_sa, &cert_request_eng));
        EXECUTE(ecert_request_set_subj_name(cert_request_eng, subject));
        EXECUTE(ecert_request_set_subj_dir_attr(cert_request_eng, subject_attr));
        EXECUTE(ecert_request_generate(cert_request_eng, &subject_cert_request));

        /* Запись cert_request. */
        EXECUTE(creq_encode(subject_cert_request, &encoded));
        save_ba_to_file(encoded, res_folder, "userfiz/request.csr");
        ba_free(encoded);
        encoded = NULL;

        /* Чтение закрытого ключа и сертификата подписчика. */
        load_ba_from_file(&issuer_key_body, res_folder, "root/private.key");
        load_certificate(res_folder, "root/certificate.cer", &issuer_cert);

        extgen_userfiz(subject_spki, issuer_cert, subject_cert_request, &extensions);
        IS_NULL(extensions);

        tprintf("        - Создание сертификата для физических лиц (%s).\n", res_folder);

        generate_cert_core(subject_cert_request,
                &not_before,
                &not_after,
                serial,
                extensions,
                issuer_key_body,
                issuer_cert,
                &subject_cert);

        /* Запись сформированного сертификата. */
        EXECUTE(cert_encode(subject_cert, &encoded));
        save_ba_to_file(encoded, res_folder, "userfiz/certificate.cer");

        const ByteArray *certs[2] = {NULL, NULL};
        certs[0] = encoded;
        certs[1] = NULL;
        EXECUTE(pkcs12_set_certificates(subject_storage, certs));


        EXECUTE(pkcs12_encode(subject_storage, &subject_storage_body));
        save_ba_to_file(subject_storage_body, res_folder, "userfiz/private.key");

        ba_free(encoded);
        encoded = NULL;
        ba_free(issuer_key_body);
        issuer_key_body = NULL;
        pkcs12_free(subject_storage);
        subject_storage = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;

        cert_free(subject_cert);
        subject_cert = NULL;

        creq_free(subject_cert_request);
        subject_cert_request = NULL;

        exts_free(extensions);
        extensions = NULL;
        spki_free(subject_spki);
        subject_spki = NULL;
        ecert_request_free(cert_request_eng);
        cert_request_eng = NULL;

        sign_adapter_free(subject_sa);
        subject_sa = NULL;

        ba_free(subject_storage_body);
        subject_storage_body = NULL;
    }
}

/** Генерация сертификата для юридических лиц. */
void generate_user_ur_certificate(void)
{
    int i;
    time_t not_before;
    time_t not_after;
    struct tm *timeinfo = NULL;

    ByteArray *encoded = NULL;

    Pkcs12Ctx *subject_storage = NULL;
    ByteArray *issuer_storage_body = NULL;
    ByteArray *subject_storage_body = NULL;

    Certificate_t *issuer_cert = NULL;
    Certificate_t *subject_cert = NULL;
    CertificationRequest_t *subject_cert_request = NULL;

    Extensions_t *extensions = NULL;
    SubjectPublicKeyInfo_t *subject_spki = NULL;

    DigestAdapter *subject_da = NULL;
    SignAdapter   *subject_sa = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    char subject_attr[] = "{1.2.804.2.1.1.1.11.1.4.2.1=23456}";
    char *res_folder;

    /* Серийный номер сертификата. */
    const unsigned char serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x03
    };

    /* Информация о получателе сертификата. */
    const char subject[] =
            "{O=ООО ТЕСТ}"
            "{OU=КЗИ}"
            "{CN=ТЕСТ}"
            "{SN=1234567890555}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}";

    /* UTC time 25.01.23 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {

        res_folder = (char *)dstu_params_name_map[i];

        tprintf("        - Генерация ключевой пары (%s).\n", res_folder);

        generate_dstu_keypair(dstu_params[i], cipher_params, &subject_storage);
        IS_NULL(subject_storage);

        EXECUTE(pkcs12_get_sign_adapter(subject_storage, &subject_sa));
        EXECUTE(subject_sa->get_pub_key(subject_sa, &subject_spki));
        EXECUTE(digest_adapter_init_by_aid(&subject_spki->algorithm, &subject_da));
        EXECUTE(ecert_request_alloc(subject_sa, &cert_request_eng));
        EXECUTE(ecert_request_set_subj_name(cert_request_eng, subject));
        EXECUTE(ecert_request_set_subj_dir_attr(cert_request_eng, subject_attr));
        EXECUTE(ecert_request_generate(cert_request_eng, &subject_cert_request));

        /* Запись subject_cert_request. */
        EXECUTE(creq_encode(subject_cert_request, &encoded));
        save_ba_to_file(encoded, res_folder, "userur/request.csr");

        ba_free(encoded);
        encoded = NULL;

        /* Чтение закрытого ключа и сертификата подписчика. */
        load_ba_from_file(&issuer_storage_body, res_folder, "root/private.key");
        load_certificate(res_folder, "root/certificate.cer", &issuer_cert);

        extgen_userur(issuer_cert, subject_spki, subject_da, subject_cert_request, &extensions);
        IS_NULL(extensions);

        tprintf("        - Создание сертификата для юридических лиц (%s).\n", res_folder);

        generate_cert_core(subject_cert_request, &not_before, &not_after, serial, extensions, issuer_storage_body, issuer_cert,
                &subject_cert);


        /* Запись сформированного сертификата. */
        EXECUTE(cert_encode(subject_cert, &encoded));
        save_ba_to_file(encoded, res_folder, "userur/certificate.cer");

        const ByteArray *certs[2] = {NULL, NULL};
        certs[0] = encoded;
        certs[1] = NULL;
        EXECUTE(pkcs12_set_certificates(subject_storage, certs));


        EXECUTE(pkcs12_encode(subject_storage, &subject_storage_body));
        save_ba_to_file(subject_storage_body, res_folder, "userur/private.key");
        ba_free(subject_storage_body);
        subject_storage_body = NULL;

        ba_free(encoded);
        encoded = NULL;
        ba_free(issuer_storage_body);
        issuer_storage_body = NULL;
        pkcs12_free(subject_storage);
        subject_storage = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;

        cert_free(subject_cert);
        subject_cert = NULL;

        creq_free(subject_cert_request);
        subject_cert_request = NULL;

        exts_free(extensions);
        extensions = NULL;
        spki_free(subject_spki);
        subject_spki = NULL;
        ecert_request_free(cert_request_eng);
        cert_request_eng = NULL;

        digest_adapter_free(subject_da);
        subject_da = NULL;
        sign_adapter_free(subject_sa);
        subject_sa = NULL;
    }
}

static void create_signed_data_container(const ByteArray *data,
        const Certificate_t *cert,
        SignAdapter *sa,
        bool set_save_cert,
        const Attributes_t *signed_attrs,
        const Attributes_t *unsigned_attrs,
        ContentInfo_t **content)
{
    ContentInfo_t *container = NULL;
    SignedData_t *signed_data = NULL;

    SignedDataEngine *signed_data_ctx = NULL;
    SignerInfoEngine *signer_info_ctx = NULL;

    DigestAdapter *da = NULL;

    /*
     * Настройка контекста для формирования подписи под запросом на
     * сертификат и под самоподписанным сертификатом.
     */

    EXECUTE(digest_adapter_init_by_cert(cert, &da));

    EXECUTE(sa->set_cert(sa, cert));
    EXECUTE(esigner_info_alloc(sa, da, NULL, &signer_info_ctx));

    if (signed_attrs) {
        EXECUTE(esigner_info_set_signed_attrs(signer_info_ctx, signed_attrs));
    }

    if (unsigned_attrs) {
        EXECUTE(esigner_info_set_unsigned_attrs(signer_info_ctx, unsigned_attrs));
    }

    EXECUTE(esigned_data_alloc(signer_info_ctx, &signed_data_ctx));
    EXECUTE(esigned_data_set_data(signed_data_ctx, oids_get_oid_numbers_by_id(OID_DATA_ID), data, true));

    if (set_save_cert) {
        EXECUTE(esigned_data_add_cert(signed_data_ctx, cert));
    }

    EXECUTE(esigned_data_generate(signed_data_ctx, &signed_data));

    container = cinfo_alloc();
    IS_NULL(container);

    EXECUTE(cinfo_init_by_signed_data(container, signed_data));

    esigned_data_free(signed_data_ctx);

    digest_adapter_free(da);

    sdata_free(signed_data);

    *content = container;
}

static void verify_signed_data_container(const ByteArray *data)
{
    int i;

    ContentInfo_t  *container = NULL;
    SignedData_t *signed_data = NULL;

    CertificateSet_t *certs = NULL;

    container = cinfo_alloc();
    IS_NULL(container);

    EXECUTE(cinfo_decode(container, data));
    EXECUTE(cinfo_get_signed_data(container, &signed_data));
    EXECUTE(sdata_get_certs(signed_data, &certs));

    for (i = 0; i < certs->list.count; i++) {
        CertificateChoices_t *choice = certs->list.array[i];

        DigestAdapter *da = NULL;
        VerifyAdapter *va = NULL;

        EXECUTE(digest_adapter_init_default(&da));
        EXECUTE(verify_adapter_init_by_cert(&choice->choice.certificate, &va));

        EXECUTE(sdata_verify_internal_data_by_adapter(signed_data, da, va, i));
        EXECUTE(sdata_verify_internal_data_by_adapter(signed_data, da, va, i));

        digest_adapter_free(da);
        verify_adapter_free(va);
    }

    ASN_FREE(get_CertificateSet_desc(), certs);
    sdata_free(signed_data);
    cinfo_free(container);
}

static void create_ocsp_request(const Certificate_t *root_cert,
        const Certificate_t *user_cert,
        const Certificate_t *ocsp_cert,
        const Pkcs12Ctx *storage,
        int timeout,
        bool has_nonce,
        OCSPRequest_t **ocsp_request)
{
    OCSPRequest_t *request = NULL;

    OcspRequestEngine *eocsp_request = NULL;

    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;

    VerifyAdapter *root_va = NULL;
    VerifyAdapter *ocsp_va = NULL;

    ByteArray *nonce = ba_alloc_by_len(20);
    (void)timeout;

    EXECUTE(ba_set(nonce, 0xaf));

    EXECUTE(digest_adapter_init_default(&da));
    EXECUTE(verify_adapter_init_by_cert(root_cert, &root_va));
    EXECUTE(verify_adapter_init_by_cert(ocsp_cert, &ocsp_va));

    EXECUTE(pkcs12_get_sign_adapter(storage, &sa));
    EXECUTE(sa->set_cert(sa, user_cert));

    EXECUTE(eocspreq_alloc(has_nonce, root_va, ocsp_va, sa, da, &eocsp_request));
    EXECUTE(eocspreq_add_cert(eocsp_request, user_cert));
    EXECUTE(eocspreq_generate(eocsp_request, nonce, &request));

    ba_free(nonce);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    verify_adapter_free(root_va);
    verify_adapter_free(ocsp_va);
    eocspreq_free(eocsp_request);

    *ocsp_request = request;

}

static void create_ocsp_response(const OCSPRequest_t *ocsp_request,
        const Certificate_t *root_cert,
        const Certificate_t *ocsp_cert,
        const CertificateLists_t *crls,
        const Pkcs12Ctx *storage,
        time_t current_time,
        OCSPResponse_t **response)
{
    OCSPResponse_t *ocsp_response = NULL;

    OcspResponseEngine *resp_ctx = NULL;

    SignAdapter *ocsp_sa = NULL;
    DigestAdapter *resp_adapter = NULL;

    VerifyAdapter *req_va = NULL;
    VerifyAdapter *root_va = NULL;

    EXECUTE(verify_adapter_init_by_cert(root_cert, &root_va));
    EXECUTE(pkcs12_get_sign_adapter(storage, &ocsp_sa));
    EXECUTE(ocsp_sa->set_cert(ocsp_sa, ocsp_cert));
    EXECUTE(digest_adapter_init_default(&resp_adapter));

    EXECUTE(eocspresp_alloc(root_va, ocsp_sa, crls, resp_adapter, true, true, OCSP_RESPONSE_BY_HASH_KEY, &resp_ctx));

    eocspresp_set_sign_required(resp_ctx, true);

    if (ocsp_request->optionalSignature) {
        verify_adapter_init_by_cert(ocsp_request->optionalSignature->certs->list.array[0], &req_va);
    }

    EXECUTE(eocspresp_generate(resp_ctx, ocsp_request, req_va, current_time, &ocsp_response));

    sign_adapter_free(ocsp_sa);
    digest_adapter_free(resp_adapter);

    verify_adapter_free(root_va);
    verify_adapter_free(req_va);

    eocspresp_free(resp_ctx);

    *response = ocsp_response;
}

static void create_complete_revocation_references(const CertificateList_t *crl, Attribute_t **attr)
{
    int ret = RET_OK;
    CrlIdentifier_t *crl_id = NULL;
    ByteArray *ext_value = NULL;

    AlgorithmIdentifier_t *aid = NULL;
    OCTET_STRING_t *hash_value = NULL;

    CrlOcspRef_t *crl_ocsp_ref = NULL;
    CRLListID_t *crl_list_ids = NULL;
    CrlValidatedID_t *crl_validated_id = NULL;
    CompleteRevocationRefs_t *crl_refs = NULL;

    ByteArray *digest = NULL;
    ByteArray *hash = NULL;

    DigestAdapter *da = NULL;

    EXECUTE(crl_encode(crl, &hash));

    EXECUTE(digest_adapter_init_default(&da));
    EXECUTE(da->update(da, hash));
    EXECUTE(da->final(da, &digest));

    EXECUTE(da->get_alg(da, &aid));
    EXECUTE(asn_create_octstring_from_ba(digest, &hash_value));

    ASN_ALLOC(crl_id);
    EXECUTE(asn_copy(get_Name_desc(), &crl->tbsCertList.issuer, &crl_id->crlissuer));

    if (crl->tbsCertList.thisUpdate.present == PKIXTime_PR_utcTime) {
        EXECUTE(asn_copy(get_UTCTime_desc(), &crl->tbsCertList.thisUpdate.choice.utcTime, &crl_id->crlIssuedTime));
    } else if (crl->tbsCertList.thisUpdate.present == PKIXTime_PR_generalTime) {
        /* TODO: convert General to UTC */
    } else {
        return;
    }

    EXECUTE(exts_get_ext_value_by_oid(crl->tbsCertList.crlExtensions,
            oids_get_oid_numbers_by_id(OID_CRL_NUMBER_EXTENSION_ID), &ext_value));

    if (ext_value != NULL) {
        CRLNumber_t *crl_number = NULL;
        ASN_ALLOC(crl_number);
        EXECUTE(asn_ba2INTEGER(ext_value, crl_number));
        crl_id->crlNumber = crl_number;
        crl_number = NULL;
    }

    ASN_ALLOC(crl_validated_id);
    crl_validated_id->crlIdentifier = crl_id;
    crl_validated_id->crlHash.present = OtherHash_PR_otherHash;
    EXECUTE(asn_copy(get_AlgorithmIdentifier_desc(), aid, &crl_validated_id->crlHash.choice.otherHash.hashAlgorithm));
    EXECUTE(asn_copy(get_OCTET_STRING_desc(), hash_value, &crl_validated_id->crlHash.choice.otherHash.hashValue));

    ASN_ALLOC(crl_list_ids);
    ASN_SET_ADD(&crl_list_ids->crls.list, crl_validated_id);

    ASN_ALLOC(crl_ocsp_ref);
    crl_ocsp_ref->crlids = crl_list_ids;

    ASN_ALLOC(crl_refs);
    ASN_SET_ADD(&crl_refs->list, crl_ocsp_ref);

    EXECUTE(init_attr(attr, oids_get_oid_numbers_by_id(OID_AA_ETS_REVOCATION_REFS_ID), get_CompleteRevocationRefs_desc(),
            crl_refs));

cleanup:

    ba_free(digest);

    aid_free(aid);
    ASN_FREE(get_OCTET_STRING_desc(), hash_value);
    ASN_FREE(get_CompleteRevocationRefs_desc(), crl_refs);
    ba_free(ext_value);

    digest_adapter_free(da);
    ba_free(hash);
}

static void create_complete_certificate_references(const Certificate_t *cert, Attribute_t **attr)
{
    OtherCertID_t *other_cert_id = NULL;
    CompleteCertificateRefs_t *cert_refs = NULL;
    OCTET_STRING_t *hash_value = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *digest = NULL;
    ByteArray *encoded = NULL;
    DigestAdapter *da = NULL;
    int ret = RET_OK;

    EXECUTE(cert_encode(cert, &encoded));

    EXECUTE(digest_adapter_init_default(&da));
    EXECUTE(da->update(da, encoded));
    EXECUTE(da->final(da, &digest));

    EXECUTE(da->get_alg(da, &aid));
    EXECUTE(asn_create_octstring_from_ba(digest, &hash_value));

    ASN_ALLOC(other_cert_id);
    other_cert_id->otherCertHash.present = OtherHash_PR_otherHash;
    EXECUTE(asn_copy(get_AlgorithmIdentifier_desc(), aid, &other_cert_id->otherCertHash.choice.otherHash.hashAlgorithm));
    EXECUTE(asn_copy(get_OCTET_STRING_desc(), hash_value, &other_cert_id->otherCertHash.choice.otherHash.hashValue));

    ASN_ALLOC(cert_refs);
    ASN_SET_ADD(&cert_refs->list, other_cert_id);

    EXECUTE(init_attr(attr, oids_get_oid_numbers_by_id(OID_AA_ETS_CERTIFICATE_REFS_ID), get_CompleteCertificateRefs_desc(),
            cert_refs));

cleanup:

    ba_free(encoded);
    ba_free(digest);

    aid_free(aid);
    ASN_FREE(get_OCTET_STRING_desc(), hash_value);
    ASN_FREE(get_CompleteCertificateRefs_desc(), cert_refs);

    digest_adapter_free(da);
}

static void create_tsp_request(const ByteArray *data, OBJECT_IDENTIFIER_t *policy, TimeStampReq_t **tsp)
{
    TimeStampReq_t *request = NULL;
    DigestAdapter *da = NULL;

    EXECUTE(digest_adapter_init_default(&da));
    EXECUTE(etspreq_generate(da, data, NULL, policy, true, &request));
    IS_NULL(request);

    digest_adapter_free(da);

    *tsp = request;
}

static void create_tsp_response(const Certificate_t *tsp_cert,
        const ByteArray *tsp_request,
        const Pkcs12Ctx *tsp_storage,
        const INTEGER_t *serial_number,
        TimeStampResp_t **tsp)
{
    time_t current_time;
    int ret = RET_OK;

    TimeStampResp_t *tsp_response = NULL;

    AlgorithmIdentifier_t *hash_alg = NULL;
    DigestAlgorithmIdentifiers_t *tsp_digest_algs = NULL;

    DigestAdapter *da = NULL;
    SignAdapter *sa = NULL;
    AdaptersMap *tsp_map = NULL;

    EXECUTE(aid_create_gost3411(&hash_alg));

    ASN_ALLOC(tsp_digest_algs);
    IS_NULL(tsp_digest_algs);

    ASN_SET_ADD(tsp_digest_algs, hash_alg);

    /* Адаптер хеширования с SBOX по умолчанию. */
    EXECUTE(digest_adapter_init_default(&da));
    EXECUTE(pkcs12_get_sign_adapter(tsp_storage, &sa));
    EXECUTE(sa->set_cert(sa, tsp_cert));

    tsp_map = adapters_map_alloc();
    IS_NULL(tsp_map);

    adapters_map_add(tsp_map, da, sa);

    time(&current_time);

    EXECUTE(etspresp_generate(tsp_map, tsp_request, serial_number, tsp_digest_algs, &current_time, &tsp_response));

    *tsp = tsp_response;

cleanup:

    adapters_map_free(tsp_map);
    ASN_FREE(get_DigestAlgorithmIdentifiers_desc(), tsp_digest_algs);
}

static void create_revocation_values(const Certificate_t *root_cert,
        const Certificate_t *issuer_cert,
        const Certificate_t *ocsp_cert,
        CertificateList_t *full_crl,
        CertificateList_t *delta_crl,
        const Pkcs12Ctx *user_storage,
        const Pkcs12Ctx *storage,
        Attribute_t **attr)
{
    int ret = RET_OK;
    CertificateLists_t *crls = NULL;
    RevocationValues_t *rvalues = NULL;

    OCSPRequest_t *ocsp_req = NULL;
    OCSPResponse_t *ocsp_resp = NULL;

    BasicOCSPResponse_t *bocsp_resp = NULL;
    ResponseBytes_t *resp_bytes = NULL;

    struct tm *timeinfo = NULL;
    time_t current_time;

    create_ocsp_request(root_cert, issuer_cert, ocsp_cert, user_storage, 2, true, &ocsp_req);
    IS_NULL(ocsp_req);

    ASN_ALLOC(crls);
    ASN_SET_ADD(&crls->list, full_crl);
    ASN_SET_ADD(&crls->list, delta_crl);

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    current_time = mktime(timeinfo);
    free(timeinfo);

    create_ocsp_response(ocsp_req, root_cert, ocsp_cert, crls, storage, current_time, &ocsp_resp);
    IS_NULL(ocsp_resp);

    EXECUTE(ocspresp_get_response_bytes(ocsp_resp, &resp_bytes));
    bocsp_resp = asn_decode_with_alloc(get_BasicOCSPResponse_desc(), resp_bytes->response.buf, resp_bytes->response.size);
    IS_NULL(bocsp_resp);

    ASN_ALLOC(rvalues);
    ASN_ALLOC(rvalues->ocspVals);
    EXECUTE(ASN_SET_ADD(&rvalues->ocspVals->list, bocsp_resp));

    EXECUTE(init_attr(attr, oids_get_oid_numbers_by_id(OID_AA_ETS_REVOCATION_VALUES_ID), get_RevocationValues_desc(),
            rvalues));

cleanup:

    ocspreq_free(ocsp_req);
    ocspresp_free(ocsp_resp);

    ASN_FREE(get_CertificateLists_desc(), crls);
    ASN_FREE(get_ResponseBytes_desc(), resp_bytes);
    ASN_FREE(get_RevocationValues_desc(), rvalues);
}

void generate_signed_data_container(void)
{
    int i;
    ByteArray *data = NULL;
    int ret = RET_OK;

    ByteArray *user_storage_body = NULL;
    ByteArray *buffer = NULL;
    ByteArray *storage_body = NULL;
    Pkcs12Ctx *storage = NULL;
    ByteArray *encoded = NULL;

    Certificate_t *root_cert = NULL;
    Certificate_t *user_cert = NULL;
    ContentInfo_t *content_info = NULL;

    int format;
    char *res_folder;
    OBJECT_IDENTIFIER_t *policy = NULL;

    /* CAdES-X types. */
    Certificate_t *ocsp_cert = NULL;
    Certificates_t *complete_values = NULL;

    /* CAdES-C types. */
    Certificate_t *tsp_cert = NULL;
    ContentInfo_t *ts_token = NULL;
    INTEGER_t *sn = NULL;

    TimeStampReq_t *tsp_req = NULL;
    TimeStampResp_t *tsp_resp = NULL;

    /* EPES types. */
    Attribute_t *attr = NULL;
    SignaturePolicyIdentifier_t *spi = NULL;

    /* General types. */
    CertificateList_t *full_crl = NULL;
    CertificateList_t *delta_crl = NULL;

    SignedData_t *sdata = NULL;
    SignerInfo_t *sinfo = NULL;
    SignerInfos_t *sinfos = NULL;

    Attributes_t *attrs = NULL;

    Pkcs12Ctx *user_storage = NULL;
    SignAdapter *user_sa = NULL;

    for (i = 0; i < dstu_params_count; i++) {

        res_folder = (char *)dstu_params_name_map[i];

        /* Инициализация сертификата подписчика. */
        load_ba_from_file(&user_storage_body, res_folder, "userfiz/private.key");
        load_certificate(res_folder, "userfiz/certificate.cer", &user_cert);

        EXECUTE(pkcs12_decode(NULL, user_storage_body, DEFAULT_STORAGE_PASSWORD, &user_storage));
        EXECUTE(pkcs12_select_key(user_storage, NULL, DEFAULT_KEY_PASSWORD));
        EXECUTE(pkcs12_get_sign_adapter(user_storage, &user_sa));

        data = ba_alloc_by_len(100);
        EXECUTE(ba_set(data, 0xf0));

        tprintf("        - Генерация контейнера подписи (%s).\n", res_folder);

        create_signed_data_container(data, user_cert, user_sa, true, NULL, NULL, &content_info);
        IS_NULL(content_info);


        EXECUTE(cinfo_encode(content_info, &buffer));
        save_ba_to_file(buffer, res_folder, "userfiz/signed_data_container.p7s");

        tprintf("        - Проверка подписи (%s).\n", res_folder);

        verify_signed_data_container(buffer);

        EXECUTE(cinfo_get_signed_data(content_info, &sdata));
        IS_NULL(sdata);

        EXECUTE(sdata_get_signer_info_by_idx(sdata, 0, &sinfo));
        IS_NULL(sinfo);

        EXECUTE(sinfo_get_format(sinfo, &format));
        assert_true(format == CADES_BES_FORMAT);

        ba_free(buffer);
        buffer = NULL;

        sinfo_free(sinfo);
        sinfo = NULL;

        sdata_free(sdata);
        sdata = NULL;

        cinfo_free(content_info);
        content_info = NULL;

        tprintf("        - Генерация контейнера подписи без сертификата (%s).\n",
                res_folder);

        create_signed_data_container(data, user_cert, user_sa, false, NULL, NULL, &content_info);
        IS_NULL(content_info);


        EXECUTE(cinfo_encode(content_info, &buffer));
        save_ba_to_file(buffer, res_folder, "userfiz/signed_data_container_without_cert.p7s");

        ba_free(buffer);
        buffer = NULL;

        cinfo_free(content_info);
        content_info = NULL;

        /** Генерация контейнера подписи формата EPES. */

        ASN_ALLOC(spi);
        spi->present = SignaturePolicyIdentifier_PR_signaturePolicyId;
        EXECUTE(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_UKR_EDS_CP_ID), &spi->choice.signaturePolicyId.sigPolicyId));
        EXECUTE(init_attr(&attr, oids_get_oid_numbers_by_id(OID_AA_ETS_SIG_POLICY_ID), get_SignaturePolicyIdentifier_desc(),
                spi));

        ASN_ALLOC(attrs);
        ASN_SET_ADD(&attrs->list, attr);
        attr = NULL;

        tprintf("        - Генерация контейнера подписи формата EPES (%s).\n", res_folder);

        create_signed_data_container(data,  user_cert, user_sa, true, attrs, NULL, &content_info);
        IS_NULL(content_info);


        EXECUTE(cinfo_encode(content_info, &buffer));
        save_ba_to_file(buffer, res_folder, "userfiz/signed_data_container_epes.p7s");

        tprintf("        - Проверка подписи (%s).\n", res_folder);
        verify_signed_data_container(buffer);


        EXECUTE(cinfo_get_signed_data(content_info, &sdata));
        EXECUTE(sdata_get_signer_info_by_idx(sdata, 0, &sinfo));

        EXECUTE(sinfo_get_format(sinfo, &format));
        assert_true(format == (CADES_BES_FORMAT | CADES_EPES_FORMAT));

        ba_free(buffer);
        buffer = NULL;

        sinfo_free(sinfo);
        sinfo = NULL;

        sdata_free(sdata);
        sdata = NULL;

        cinfo_free(content_info);
        content_info = NULL;

        ASN_FREE(get_Attributes_desc(), attrs);
        attrs = NULL;
        ASN_FREE(get_SignaturePolicyIdentifier_desc(), spi);
        spi = NULL;

        /** Генерация контейнера подписи формата CAdES-C. */

        /* Инициализация сертификата подписчика. */
        load_certificate(res_folder, "tsp/certificate.cer", &tsp_cert);
        load_ba_from_file(&storage_body, res_folder, "tsp/private.key");
        load_ba_from_file(&encoded, res_folder, "root/certificate.cer");

        EXECUTE(pkcs12_decode(NULL, storage_body, DEFAULT_STORAGE_PASSWORD, &storage));
        EXECUTE(pkcs12_select_key(storage, NULL, DEFAULT_KEY_PASSWORD));

        root_cert = cert_alloc();
        IS_NULL(root_cert);
        EXECUTE(cert_decode(root_cert, encoded));

        ba_free(encoded);
        encoded = NULL;

        /* Инициализация полного списка отозванных сертификатов. */
        load_ba_from_file(&encoded, res_folder, "crl/full.crl");
        full_crl = crl_alloc();
        IS_NULL(full_crl);
        EXECUTE(crl_decode(full_crl, encoded));

        ASN_ALLOC(attrs);

        create_complete_certificate_references(root_cert, &attr);
        IS_NULL(attr);
        ASN_SET_ADD(&attrs->list, attr);
        attr = NULL;

        create_complete_revocation_references(full_crl, &attr);
        IS_NULL(attr);
        ASN_SET_ADD(&attrs->list, attr);
        attr = NULL;

        tprintf("        - Генерация контейнера подписи формата CAdES-C (%s).\n", res_folder);

        create_signed_data_container(data, user_cert, user_sa, true, NULL, attrs, &content_info);
        IS_NULL(content_info);


        EXECUTE(cinfo_get_signed_data(content_info, &sdata));
        EXECUTE(sdata_get_signer_infos(sdata, &sinfos));

        sinfo = sinfos->list.array[0];
        EXECUTE(asn_OCTSTRING2ba(&sinfo->signature, &buffer));
        if (i < dstu_params_count) {
            bool is_onb;
            dstu4145_is_onb_params(dstu_params[i], &is_onb);
            EXECUTE(pkix_create_oid(is_onb ? oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_ONB_ID) :
                    oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_PB_ID),
                    &policy));
        } else {
            EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_GOST_ID), &policy));
        }

        create_tsp_request(buffer, policy, &tsp_req);
        IS_NULL(tsp_req);

        ba_free(buffer);
        buffer = NULL;

        EXECUTE(tsreq_encode(tsp_req, &buffer));

        EXECUTE(asn_create_integer_from_long(128, &sn));
        IS_NULL(sn);

        create_tsp_response(tsp_cert, buffer, storage, sn, &tsp_resp);
        IS_NULL(tsp_resp);

        ba_free(buffer);
        buffer = NULL;

        EXECUTE(tsresp_get_ts_token(tsp_resp, &ts_token));

        EXECUTE(init_attr(&attr, oids_get_oid_numbers_by_id(OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID), get_ContentInfo_desc(),
                ts_token));

        cinfo_free(ts_token);
        ts_token = NULL;

        EXECUTE(sinfo_add_unsigned_attr(sinfo, attr));
        ASN_FREE(get_Attribute_desc(), attr);
        attr = NULL;
        sinfo = NULL;

        EXECUTE(sdata_set_signer_infos(sdata, sinfos));

        cinfo_free(content_info);

        content_info = cinfo_alloc();
        EXECUTE(cinfo_init_by_signed_data(content_info, sdata));

        EXECUTE(cinfo_encode(content_info, &buffer));
        save_ba_to_file(buffer, res_folder, "userfiz/signed_data_container_c.p7s");

        tprintf("        - Проверка подписи (%s).\n", res_folder);
        verify_signed_data_container(buffer);

        sdata_free(sdata);
        sdata = NULL;

        EXECUTE(cinfo_get_signed_data(content_info, &sdata));
        IS_NULL(sdata);

        EXECUTE(sdata_get_signer_info_by_idx(sdata, 0, &sinfo));
        IS_NULL(sinfo);

        EXECUTE(sinfo_get_format(sinfo, &format));
        assert_true(format == (CADES_BES_FORMAT | CADES_C_FORMAT));

        ba_free(encoded);
        encoded = NULL;

        ba_free(buffer);
        buffer = NULL;

        ba_free(storage_body);
        storage_body = NULL;
        pkcs12_free(storage);
        storage = NULL;

        sinfo_free(sinfo);
        sinfo = NULL;

        sdata_free(sdata);
        sdata = NULL;

        cert_free(tsp_cert);
        tsp_cert = NULL;

        cinfo_free(content_info);
        content_info = NULL;

        tsreq_free(tsp_req);
        tsp_req = NULL;
        tsresp_free(tsp_resp);
        tsp_resp = NULL;

        ASN_FREE(get_INTEGER_desc(), sn);
        sn = NULL;
        ASN_FREE(get_Attributes_desc(), attrs);
        attrs = NULL;
        ASN_FREE(get_SignerInfos_desc(), sinfos);
        sinfos = NULL;

        /** Генерация контейнера подписи формата CAdES-X. */

        load_ba_from_file(&storage_body, res_folder, "ocsp/private.key");
        load_certificate(res_folder, "ocsp/certificate.cer", &ocsp_cert);
        load_ba_from_file(&encoded, res_folder, "crl/delta.crl");

        EXECUTE(pkcs12_decode(NULL, storage_body, DEFAULT_STORAGE_PASSWORD, &storage));
        EXECUTE(pkcs12_select_key(storage, NULL, DEFAULT_KEY_PASSWORD));

        delta_crl = crl_alloc();
        IS_NULL(delta_crl);
        EXECUTE(crl_decode(delta_crl, encoded));

        ba_free(encoded);
        encoded = NULL;

        ASN_ALLOC(complete_values);
        ASN_SET_ADD(&complete_values->list, root_cert);

        EXECUTE(init_attr(&attr, oids_get_oid_numbers_by_id(OID_AA_ETS_CERT_VALUES_ID), get_Certificates_desc(),
                complete_values));

        ASN_ALLOC(attrs);
        ASN_SET_ADD(&attrs->list, attr);
        attr = NULL;

        create_revocation_values(root_cert, user_cert, ocsp_cert, full_crl, delta_crl, user_storage, storage, &attr);
        ASN_SET_ADD(&attrs->list, attr);
        attr = NULL;

        tprintf("        - Генерация контейнера подписи формата CAdES-X (%s).\n", res_folder);

        create_signed_data_container(data, user_cert, user_sa, true, NULL, attrs, &content_info);
        IS_NULL(content_info);


        EXECUTE(cinfo_encode(content_info, &buffer));
        save_ba_to_file(buffer, res_folder, "userfiz/signed_data_container_x.p7s");

        tprintf("        - Проверка подписи (%s).\n", res_folder);
        verify_signed_data_container(buffer);


        sdata_free(sdata);
        sdata = NULL;
        EXECUTE(cinfo_get_signed_data(content_info, &sdata));
        IS_NULL(sdata);

        EXECUTE(sdata_get_signer_info_by_idx(sdata, 0, &sinfo));
        IS_NULL(sinfo);

        EXECUTE(sinfo_get_format(sinfo, &format));
        assert_true(format == (CADES_BES_FORMAT | CADES_X_FORMAT));

        ba_free(buffer);
        buffer = NULL;

        ba_free(user_storage_body);
        user_storage_body = NULL;

        ba_free(storage_body);
        storage_body = NULL;

        sinfo_free(sinfo);
        sinfo = NULL;

        sdata_free(sdata);
        sdata = NULL;

        cert_free(ocsp_cert);
        ocsp_cert = NULL;

        cert_free(user_cert);
        user_cert = NULL;

        cinfo_free(content_info);
        content_info = NULL;

        ba_free(data);
        data = NULL;

        ASN_FREE(get_Attributes_desc(), attrs);
        attrs = NULL;
        ASN_FREE(get_Certificates_desc(), complete_values);
        complete_values = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), policy);
        policy = NULL;

        sign_adapter_free(user_sa);
        user_sa = NULL;

        pkcs12_free(user_storage);
        user_storage = NULL;

        pkcs12_free(storage);
        storage = NULL;
    }

cleanup:

    return;
}

static void create_crl_container(const Certificate_t *cert, const Pkcs12Ctx *storage, CertificateList_t **cert_list)
{
    CRLReason_t *reason = NULL;
    CertificateList_t *crl = NULL;
    Extensions_t *extensions = NULL;

    SignAdapter   *sa = NULL;
    VerifyAdapter *va = NULL;
    DigestAdapter *da = NULL;

    CrlEngine *crl_engine = NULL;
    ByteArray *cert_sn = NULL;

    struct tm *timeinfo = NULL;
    time_t revoke_time;

    const char templ_name[] = "crl_fool_templ";

    const char templ_descr[] =
            "Шаблон корневого самоподписанного сертификата банка";

    /*
     * Настройка контекста для формирования подписи под запросом на
     * сертификат и под самоподписанным сертификатом.
     */
    /* Init adapters. */
    EXECUTE(pkcs12_get_sign_adapter(storage, &sa));
    EXECUTE(sa->set_cert(sa, cert));
    EXECUTE(verify_adapter_init_by_cert(cert, &va));
    EXECUTE(digest_adapter_init_by_cert(cert, &da));

    extgen_fullcrl(cert, &extensions);
    IS_NULL(extensions);

    /* Generate full CRL. */
    EXECUTE(ecrl_alloc(NULL, sa, va, extensions, templ_name, CRL_FULL, templ_descr, &crl_engine));

    /* UTC time 26.01.13 22:00:00. */
    timeinfo = calloc(1, sizeof(struct tm));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    revoke_time = mktime(timeinfo);
    free(timeinfo);

    asn_create_integer_from_long(CRLReason_aACompromise, &reason);
    cert_sn = ba_alloc_from_str("123");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_affiliationChanged, &reason);
    cert_sn = ba_alloc_from_str("456");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_keyCompromise, &reason);
    cert_sn = ba_alloc_from_str("789");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_certificateHold, &reason);
    cert_sn = ba_alloc_from_str("098");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_unspecified, &reason);
    cert_sn = ba_alloc_from_str("463");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    EXECUTE(ecrl_generate_diff_next_update(crl_engine, 60 * 60 * 24 * 7, &crl));

    exts_free(extensions);

    ecrl_free(crl_engine);

    sign_adapter_free(sa);
    verify_adapter_free(va);
    digest_adapter_free(da);

    *cert_list = crl;
}

static void create_delta_container(const CertificateList_t *full,
        const Certificate_t *cert,
        const Pkcs12Ctx *storage,
        CertificateList_t **cert_list)
{
    CRLReason_t *reason = NULL;
    CertificateList_t *crl = NULL;
    Extensions_t *extensions = NULL;

    SignAdapter   *sa = NULL;
    VerifyAdapter *va = NULL;
    DigestAdapter *da = NULL;

    CrlEngine *crl_engine = NULL;
    ByteArray *cert_sn = NULL;

    struct tm *timeinfo = NULL;
    time_t revoke_time;

    const char templ_name[] = "crl_delta_templ";

    const char templ_descr[] =
            "Шаблон корневого самоподписанного сертификата банка";

    EXECUTE(pkcs12_get_sign_adapter(storage, &sa));
    EXECUTE(sa->set_cert(sa, cert));
    EXECUTE(verify_adapter_init_by_cert(cert, &va));
    EXECUTE(digest_adapter_init_by_cert(cert, &da));

    ByteArray *crl_number = NULL;
    EXECUTE(crl_get_crl_number(full, &crl_number));
    extgen_deltacrl(crl_number, cert, &extensions);
    ba_free(crl_number);
    IS_NULL(extensions);

    EXECUTE(ecrl_alloc(full,
            sa,
            va,
            extensions,
            templ_name,
            CRL_DELTA,
            templ_descr,
            &crl_engine));

    /* UTC time 26.01.13 22:00:00. */
    timeinfo = calloc(1, sizeof(struct tm));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    revoke_time = mktime(timeinfo);
    free(timeinfo);

    asn_create_integer_from_long(CRLReason_aACompromise, &reason);
    cert_sn = ba_alloc_from_str("752");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_affiliationChanged, &reason);
    cert_sn = ba_alloc_from_str("3468");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_keyCompromise, &reason);
    cert_sn = ba_alloc_from_str("72349072");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_certificateHold, &reason);
    cert_sn = ba_alloc_from_str("4902");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    asn_create_integer_from_long(CRLReason_unspecified, &reason);
    cert_sn = ba_alloc_from_str("4124802");
    EXECUTE(ecrl_add_revoked_cert_by_sn(crl_engine, cert_sn, reason, &revoke_time));
    ASN_FREE(get_CRLReason_desc(), reason);
    reason = NULL;
    ba_free(cert_sn);

    EXECUTE(ecrl_generate_diff_next_update(crl_engine, 60 * 60 * 24, &crl));

    exts_free(extensions);

    ecrl_free(crl_engine);

    sign_adapter_free(sa);
    verify_adapter_free(va);
    digest_adapter_free(da);

    *cert_list = crl;
}

void generate_crl_container(void)
{
    int i;
    Certificate_t *issuer_cert = NULL;
    CertificateList_t *full_crl = NULL;
    CertificateList_t *delta_crl = NULL;

    ByteArray *encoded = NULL;
    ByteArray *storage_body;
    Pkcs12Ctx *storage = NULL;
    char *res_folder;

    for (i = 0; i < dstu_params_count; i++) {

        res_folder = (char *)dstu_params_name_map[i];

        /* Инициализация сертификата подписчика. */
        load_ba_from_file(&storage_body, res_folder, "root/private.key");
        EXECUTE(pkcs12_decode(NULL, storage_body, DEFAULT_STORAGE_PASSWORD, &storage));
        EXECUTE(pkcs12_select_key(storage, NULL, DEFAULT_KEY_PASSWORD));
        load_certificate(res_folder, "root/certificate.cer", &issuer_cert);

        tprintf("        - Генерация полного списка отозванных сертификатов - FULL CRL (%s).\n",
                res_folder);

        create_crl_container(issuer_cert, storage, &full_crl);
        if (!full_crl) {
            break;
        }

        tprintf("        - Генерация частичного списка отозванных сертификатов - DELTA CRL (%s).\n",
                res_folder);

        create_delta_container(full_crl, issuer_cert, storage, &delta_crl);
        if (!delta_crl) {
            break;
        }


        /* Запись результата. */
        EXECUTE(crl_encode(full_crl, &encoded));
        save_ba_to_file(encoded, res_folder, "crl/full.crl");
        ba_free(encoded);
        encoded = NULL;

        EXECUTE(crl_encode(delta_crl, &encoded));
        save_ba_to_file(encoded, res_folder, "crl/delta.crl");
        ba_free(encoded);
        encoded = NULL;

        ba_free(storage_body);
        storage_body = NULL;
        pkcs12_free(storage);
        storage = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;

        crl_free(full_crl);
        full_crl = NULL;

        crl_free(delta_crl);
        delta_crl = NULL;
    }
}

/* -------------------- Генерация симметричного ключа ГОСТ-28147 ------------------- */

static void create_enveloped_data_container(const OBJECT_IDENTIFIER_t *cipher_oid,
        const DhAdapter *storage_dha,
        const Certificate_t *issuer_cert,
        const Certificate_t *subject_cert,
        const ByteArray *data,
        bool save_cert,
        ContentInfo_t **content)
{
    ContentInfo_t *container = NULL;
    EnvelopedData_t *enveloped_data = NULL;

    OBJECT_IDENTIFIER_t *oid_data = NULL;
    AlgorithmIdentifier_t *cipher_alg = NULL;

    Dstu4145Ctx *issuer_dstu_ctx = NULL;
    Dstu4145Ctx *subject_dstu_ctx = NULL;
    ByteArray *gen_privkey = NULL;
    ByteArray *pubkey = NULL;
    ByteArray *qx = NULL;
    ByteArray *qy = NULL;

    DhAdapter *dha = NULL;
    CipherAdapter *ca = NULL;
    ByteArray *encrypted_data = NULL;
    EnvelopedDataEngine *enveloped_data_ctx = NULL;

    PrngCtx *prng = NULL;
    ByteArray *prng_seed = ba_alloc_by_len(PRNG_SEED_SIZE);

    EXECUTE(ba_set(prng_seed, 0));

    prng = prng_alloc(PRNG_MODE_DSTU, prng_seed);
    IS_NULL(prng);

    EXECUTE(eenvel_data_alloc(storage_dha, &enveloped_data_ctx));
    EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_DATA_ID), &oid_data));
    EXECUTE(eenvel_data_set_data(enveloped_data_ctx, oid_data, data));
    EXECUTE(eenvel_data_set_originator_cert(enveloped_data_ctx, issuer_cert));
    EXECUTE(eenvel_data_set_encription_oid(enveloped_data_ctx, cipher_oid));
    EXECUTE(eenvel_data_add_recipient(enveloped_data_ctx, subject_cert));
    EXECUTE(eenvel_data_set_save_cert_optional(enveloped_data_ctx, save_cert));
    EXECUTE(eenvel_data_set_prng(enveloped_data_ctx, prng));

    EXECUTE(eenvel_data_generate(enveloped_data_ctx, &enveloped_data, &encrypted_data));

    container = cinfo_alloc();
    IS_NULL(container);

    EXECUTE(cinfo_init_by_enveloped_data(container, enveloped_data));

    ba_free(prng_seed);
    ba_free(qx);
    ba_free(qy);
    ba_free(pubkey);
    ba_free(gen_privkey);
    dstu4145_free(issuer_dstu_ctx);
    dstu4145_free(subject_dstu_ctx);
    prng_free(prng);
    cipher_adapter_free(ca);
    dh_adapter_free(dha);
    ASN_FREE(get_OBJECT_IDENTIFIER_desc(), oid_data);
    aid_free(cipher_alg);
    env_data_free(enveloped_data);
    eenvel_data_free(enveloped_data_ctx);
    *content = container;
    ba_free(encrypted_data);
}

/**
 * Рашифровывает сообщение из контейнера с защищенными данными.
 *
 * @param ci             контейнер с защищенными данными
 * @param subject_priv_key закрытый ключ получателя
 * @param subject_priv_key_len размер закрытого ключа получателя
 * @param subject_cert    сертификат получателя
 * @param issuer_cert_optional сертификат подписчика, если не указан, то ищется в контейнере с защищенными данными
 * @param decrypted_data расшифрованные данные
 * @param len размер расшифрованных данных
 *
 * @return расшифрованое сообщение
 */
static void decrypt_enveloped_data(const ContentInfo_t *ci,
        const DhAdapter *subject_dha,
        const Certificate_t *subject_cert,
        const Certificate_t *issuer_cert_optional,
        ByteArray **decrypted_data)
{
    EnvelopedData_t *ed = NULL;
    Certificate_t *issuer_cert = NULL;
    AlgorithmIdentifier_t *content_encryption_alg = NULL;

    ByteArray *issuer_public_key = NULL;
    ByteArray *rnd_bytes = NULL;
    ByteArray *session_key = NULL;
    ByteArray *decrypt_session_key = NULL;
    CipherAdapter *ca = NULL;

    EXECUTE(cinfo_get_enveloped_data(ci, &ed));
    EXECUTE(env_decrypt_data(ed, NULL, issuer_cert_optional, subject_dha, subject_cert, decrypted_data));

    ba_free(rnd_bytes);
    ba_free(session_key);
    ba_free(decrypt_session_key);
    ba_free(issuer_public_key);

    cipher_adapter_free(ca);

    env_data_free(ed);
    cert_free(issuer_cert);

    aid_free(content_encryption_alg);
}

static void get_first_dha(const ByteArray *storage_body, DhAdapter **dha)
{
    Pkcs12Ctx *storage = NULL;

    EXECUTE(pkcs12_decode(NULL, storage_body, DEFAULT_STORAGE_PASSWORD, &storage));
    EXECUTE(pkcs12_select_key(storage, NULL, DEFAULT_KEY_PASSWORD));
    EXECUTE(pkcs12_get_dh_adapter(storage, dha));
    pkcs12_free(storage);
}

#define ASSERT_EQUALS_BA(expected, actual)                                                              \
{                                                                                                       \
    size_t _exp_len = ba_get_len(expected);                                                               \
    size_t _act_len = ba_get_len(actual);                                                                 \
    assert_equals(&_exp_len, &_act_len, sizeof(size_t), __FILE__, __LINE__);                            \
    assert_equals(ba_get_buf(expected), ba_get_buf(actual), ba_get_len(actual), __FILE__, __LINE__);    \
}

bool assert_equals(const void *expected, const void *actual, size_t size, char *file, int line)
{
    size_t i = 0;
    uint8_t *exp = (uint8_t *) expected;
    uint8_t *act = (uint8_t *) actual;
    if (memcmp(expected, actual, size)) {
        printf("-------------------------------------------------------------------------------\n");
        printf("%s:%i: Assert failed.\n", file, line);
        printf("Expected bytes:\n");
        for (i = 0; i < size; i++) {
            printf(" 0x%02x,", exp[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
        printf("Actual bytes: \n");
        for (i = 0; i < size; i++) {
            printf(" 0x%02x,", act[i]);
            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("-------------------------------------------------------------------------------\n");

        error_count++;
        return false;
    }

    return true;
}

void generate_enveloped_data_static(void)
{
    size_t i;
    ByteArray *data = ba_alloc_by_len(100);

    ByteArray *issuer_storage_body = NULL;
    Pkcs12Ctx *issuer_storage = NULL;
    DhAdapter *issuer_dha = NULL;

    ByteArray *subject_storage_body = NULL;
    Pkcs12Ctx *subject_storage = NULL;
    DhAdapter *subject_dha = NULL;

    ByteArray *decrypted_data = NULL;
    ByteArray *buffer = NULL;

    Certificate_t *issuer_cert = NULL;
    Certificate_t *subject_cert = NULL;
    ContentInfo_t *enveloped_data = NULL;
    OBJECT_IDENTIFIER_t *cipher_oid = NULL;

    EXECUTE(ba_set(data, 0xf0));

    for (i = 0; i < sizeof(dstu_params_id_map) / sizeof(Dstu4145ParamsId); i++) {

        load_certificate(dstu_params_name_map[i], "root/certificate.cer", &issuer_cert);
        load_certificate(dstu_params_name_map[i], "userfiz/certificate.cer", &subject_cert);

        load_ba_from_file(&issuer_storage_body, dstu_params_name_map[i], "root/private.key");
        get_first_dha(issuer_storage_body, &issuer_dha);
        IS_NULL(issuer_dha);

        load_ba_from_file(&subject_storage_body, dstu_params_name_map[i], "userfiz/private.key");
        get_first_dha(subject_storage_body, &subject_dha);
        IS_NULL(subject_dha);

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме CFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется (%s).\n",
                dstu_params_name_map[i]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, false, &enveloped_data);
        IS_NULL(enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[i], "userfiz/enveloped-data-container-without-cert-cfb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[i]);

        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);

        assert_true(ba_cmp(data, decrypted_data) == 0);

        ba_free(decrypted_data);
        decrypted_data = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме CFB.\n"
                "          Сертификата отправителя в контейнере сохраняется (%s).\n",
                dstu_params_name_map[i]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, true, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[i], "userfiz/enveloped-data-container-with-cert-cfb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[i]);


        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, NULL, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);

        ba_free(decrypted_data);
        decrypted_data = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме OFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется (%s).\n",
                dstu_params_name_map[i]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, false, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[i], "userfiz/enveloped-data-container-without-cert-ofb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[i]);


        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);


        ba_free(decrypted_data);
        decrypted_data = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме OFB.\n"
                "          Сертификата отправителя в контейнере сохраняется (%s).\n",
                dstu_params_name_map[i]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, true, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[i], "userfiz/enveloped-data-container-with-cert-ofb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[i]);


        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, NULL, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);


        ba_free(decrypted_data);
        decrypted_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;

        cert_free(subject_cert);
        subject_cert = NULL;

        ba_free(issuer_storage_body);
        issuer_storage_body = NULL;

        ba_free(subject_storage_body);
        subject_storage_body = NULL;

        dh_adapter_free(issuer_dha);
        issuer_dha = NULL;
        dh_adapter_free(subject_dha);
        subject_dha = NULL;

        pkcs12_free(issuer_storage);
        issuer_storage = NULL;
        pkcs12_free(subject_storage);
        subject_storage = NULL;
    }

    ba_free(data);
}

void generate_enveloped_data_dynamic(void)
{
    size_t i;
    ByteArray *data = ba_alloc_by_len(100);
    ByteArray *decrypted_data = NULL;
    ByteArray *buffer = NULL;

    ByteArray *first_storage_body = NULL;
    DhAdapter *first_dha = NULL;

    Certificate_t *first_cert = NULL;

    ByteArray *issuer_storage_body = NULL;
    Pkcs12Ctx *issuer_storage = NULL;
    DhAdapter *issuer_dha = NULL;

    Certificate_t *issuer_cert = NULL;

    ByteArray *subject_storage_body = NULL;
    DhAdapter *subject_dha = NULL;

    Certificate_t *subject_cert = NULL;
    ContentInfo_t *enveloped_data = NULL;
    OBJECT_IDENTIFIER_t *cipher_oid = NULL;

    size_t issuer_params = 0;
    EXECUTE(ba_set(data, 0xf0));

    load_certificate(dstu_params_name_map[0], "userfiz/certificate.cer", &issuer_cert);
    load_ba_from_file(&issuer_storage_body, dstu_params_name_map[0], "userfiz/private.key");

    get_first_dha(issuer_storage_body, &issuer_dha);
    IS_NULL(issuer_dha);

    issuer_params = 0;

    load_certificate(dstu_params_name_map[0], "userfiz/certificate.cer", &first_cert);
    load_ba_from_file(&first_storage_body, dstu_params_name_map[0], "userfiz/private.key");
    get_first_dha(first_storage_body, &first_dha);
    IS_NULL(first_dha);

    for (i = 1; i < sizeof(dstu_params_id_map) / sizeof(Dstu4145ParamsId); i++) {
        load_certificate(dstu_params_name_map[i], "userfiz/certificate.cer", &subject_cert);
        load_ba_from_file(&subject_storage_body, dstu_params_name_map[i], "userfiz/private.key");
        get_first_dha(subject_storage_body, &subject_dha);
        IS_NULL(subject_dha);

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме CFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется(%s).\n",
                dstu_params_name_map[issuer_params]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, false, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[issuer_params], "userfiz/enveloped-data-container-dynamic-cfb.der");

        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[issuer_params]);


        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);

        ba_free(decrypted_data);
        decrypted_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме OFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется(%s).\n",
                dstu_params_name_map[issuer_params]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, subject_cert, data, false, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[issuer_params], "userfiz/enveloped-data-container-dynamic-ofb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[issuer_params]);


        decrypt_enveloped_data(enveloped_data, subject_dha, subject_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);


        ba_free(decrypted_data);
        decrypted_data = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        ba_free(issuer_storage_body);
        issuer_storage_body = NULL;

        ba_free(subject_storage_body);
        subject_storage_body = NULL;

        dh_adapter_free(issuer_dha);
        issuer_dha = subject_dha;
        subject_dha = NULL;

        pkcs12_free(issuer_storage);
        issuer_storage = NULL;

        cert_free(issuer_cert);
        issuer_cert = subject_cert;
        subject_cert = NULL;

        issuer_params = i;
    }

    if (issuer_cert != NULL) {

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме CFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется(%s).\n",
                dstu_params_name_map[issuer_params]);

        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_CFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, first_cert, data, false, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[issuer_params], "userfiz/enveloped-data-container-dynamic-cfb.der");


        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[issuer_params]);


        decrypt_enveloped_data(enveloped_data, first_dha, first_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);


        ba_free(decrypted_data);
        decrypted_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        tprintf("        - Генерация контейнера защищенных данных\n"
                "          с применением алгоритма шифрования ГОСТ 28147 в решиме OFB.\n"
                "          Сертификата отправителя в контейнере не сохраняется(%s).\n",
                dstu_params_name_map[issuer_params]);


        EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID), &cipher_oid));
        create_enveloped_data_container(cipher_oid, issuer_dha, issuer_cert, first_cert, data, false, &enveloped_data);

        EXECUTE(cinfo_encode(enveloped_data, &buffer));
        save_ba_to_file(buffer, dstu_params_name_map[issuer_params], "userfiz/enveloped-data-container-dynamic-ofb.der");

        ba_free(buffer);
        buffer = NULL;

        tprintf("        - Проверка контейнера (%s).\n", dstu_params_name_map[issuer_params]);


        decrypt_enveloped_data(enveloped_data, first_dha, first_cert, issuer_cert, &decrypted_data);
        IS_NULL(decrypted_data);
        ASSERT_EQUALS_BA(data, decrypted_data);

        ba_free(decrypted_data);
        decrypted_data = NULL;

        cinfo_free(enveloped_data);
        enveloped_data = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), cipher_oid);
        cipher_oid = NULL;
    }

    cert_free(issuer_cert);
    cert_free(first_cert);

    ba_free(issuer_storage_body);
    ba_free(first_storage_body);
    ba_free(data);

    dh_adapter_free(issuer_dha);
    dh_adapter_free(first_dha);
    dh_adapter_free(subject_dha);

    cert_free(subject_cert);
}

/** Генерация сертификата TSP-сервера. */
void generate_tsp_certificate(void)
{
    int i;
    struct tm *timeinfo = NULL;
    time_t not_before;
    time_t not_after;

    Certificate_t *subject_cert = NULL;
    Certificate_t *issuer_cert = NULL;
    CertificationRequest_t *subject_cert_request = NULL;

    Extensions_t *extensions = NULL;
    SubjectPublicKeyInfo_t *subject_spki = NULL;

    DigestAdapter *subject_da = NULL;
    SignAdapter *subject_sa = NULL;

    ByteArray *encoded = NULL;
    ByteArray *issuer_key = NULL;
    Pkcs12Ctx *subject_storage = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    ByteArray *subject_storage_body = NULL;

    /* Серийный номер сертификата. */
    const unsigned char tsp_serial[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00,
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x04
    };

    /* Информация о получателе сертификата. */
    const char subject[] =
            "{O=Test}"
            "{OU=ЦСК}"
            "{CN=TSP-ЦСК Test}"
            "{SN=UA-123456789-4312}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}";

    char *res_folder;

    /* UTC time 25.01.23 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {

        res_folder = (char *) dstu_params_name_map[i];

        tprintf("        - Генерация ключевой пары (%s).\n", res_folder);
        generate_dstu_keypair(dstu_params[i], cipher_params, &subject_storage);
        IS_NULL(subject_storage);

        EXECUTE(pkcs12_get_sign_adapter(subject_storage, &subject_sa));
        IS_NULL(subject_sa);

        EXECUTE(subject_sa->get_pub_key(subject_sa, &subject_spki));
        EXECUTE(digest_adapter_init_by_aid(&subject_spki->algorithm, &subject_da));

        tprintf("        - Генерация запроса на сертификат (%s).\n", res_folder);

        EXECUTE(ecert_request_alloc(subject_sa, &cert_request_eng));
        EXECUTE(ecert_request_set_subj_name(cert_request_eng, subject));
        EXECUTE(ecert_request_generate(cert_request_eng, &subject_cert_request));

        /* Запись cert_request. */
        EXECUTE(creq_encode(subject_cert_request, &encoded));
        save_ba_to_file(encoded, res_folder, "tsp/request.csr");
        ba_free(encoded);
        encoded = NULL;

        /* Чтение закрытого ключа и сертификата подписчика. */
        load_ba_from_file(&issuer_key, res_folder, "root/private.key");
        load_certificate(res_folder, "root/certificate.cer", &issuer_cert);

        extgen_tsp(subject_spki, subject_da, &issuer_cert->tbsCertificate.validity, issuer_cert, &extensions);
        IS_NULL(extensions);


        tprintf("        - Создание сертификата для TSP-сервера (%s).\n", res_folder);
        generate_cert_core(subject_cert_request, &not_before, &not_after, tsp_serial, extensions, issuer_key,
                issuer_cert, &subject_cert);


        /* Запись сформированного сертификата. */
        EXECUTE(cert_encode(subject_cert, &encoded));
        save_ba_to_file(encoded, res_folder, "tsp/certificate.cer");

        const ByteArray *certs[2] = {NULL, NULL};
        certs[0] = encoded;
        certs[1] = NULL;
        EXECUTE(pkcs12_set_certificates(subject_storage, certs));


        EXECUTE(pkcs12_encode(subject_storage, &subject_storage_body));
        save_ba_to_file(subject_storage_body, res_folder, "tsp/private.key");

        ba_free(encoded);
        encoded = NULL;
        ba_free(issuer_key);
        issuer_key = NULL;
        ba_free(subject_storage_body);
        subject_storage_body = NULL;
        pkcs12_free(subject_storage);
        subject_storage = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;
        cert_free(subject_cert);
        subject_cert = NULL;
        creq_free(subject_cert_request);
        subject_cert_request = NULL;

        digest_adapter_free(subject_da);
        subject_da = NULL;
        sign_adapter_free(subject_sa);
        subject_sa = NULL;

        exts_free(extensions);
        extensions = NULL;
        spki_free(subject_spki);
        subject_spki = NULL;
        ecert_request_free(cert_request_eng);
        cert_request_eng = NULL;
    }
}

/** Генерация запроса TSP. */
void generate_tsp_request(void)
{
    int i;
    TimeStampReq_t *tsp_request = NULL;
    ByteArray *buffer = NULL;
    ByteArray *test_data = ba_alloc_by_len(2048);
    char *res_folder;
    OBJECT_IDENTIFIER_t *policy = NULL;

    EXECUTE(ba_set(test_data, 0xa5));

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        if (i < dstu_params_count) {
            bool is_onb;
            dstu4145_is_onb_params(dstu_params[i], &is_onb);
            EXECUTE(pkix_create_oid(is_onb ? oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_ONB_ID) :
                    oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_PB_ID),
                    &policy));
        } else {
            EXECUTE(pkix_create_oid(oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_GOST_ID), &policy));
        }

        tprintf("        - Генерация TSP-запроса (%s).\n", res_folder);
        create_tsp_request(test_data, policy, &tsp_request);
        IS_NULL(tsp_request);

        EXECUTE(tsreq_encode(tsp_request, &buffer));
        save_ba_to_file(buffer, res_folder, "tsp/tsprequest.der");

        tsreq_free(tsp_request);
        tsp_request = NULL;

        ba_free(buffer);
        buffer = NULL;

        ASN_FREE(get_OBJECT_IDENTIFIER_desc(), policy);
        policy = NULL;
    }

    ba_free(test_data);
}

/** Генерация TSP ответа. */
void generate_tsp_response(void)
{
    int i;
    INTEGER_t *serial_number = NULL;
    Certificate_t *tsp_cert = NULL;
    TimeStampResp_t *tsp_response = NULL;

    ByteArray *tsp_request = NULL;
    ByteArray *encoded = NULL;
    ByteArray *tsp_storage_body = NULL;
    Pkcs12Ctx *tsp_storage = NULL;

    char *res_folder;

    EXECUTE(asn_create_integer_from_long(128, &serial_number));
    IS_NULL(serial_number);

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        load_ba_from_file(&tsp_request, res_folder, "tsp/tsprequest.der");
        load_ba_from_file(&tsp_storage_body, res_folder, "tsp/private.key");
        load_certificate(res_folder, "tsp/certificate.cer", &tsp_cert);

        EXECUTE(pkcs12_decode(NULL, tsp_storage_body, DEFAULT_STORAGE_PASSWORD, &tsp_storage));
        EXECUTE(pkcs12_select_key(tsp_storage, NULL, DEFAULT_KEY_PASSWORD));

        tprintf("        - Генерация TSP-response (%s).\n", res_folder);
        create_tsp_response(tsp_cert, tsp_request, tsp_storage, serial_number, &tsp_response);
        IS_NULL(tsp_response);

        EXECUTE(tsresp_encode(tsp_response, &encoded));
        save_ba_to_file(encoded, res_folder, "tsp/tspresponse.der");

        ba_free(tsp_request);
        tsp_request = NULL;

        tsresp_free(tsp_response);
        tsp_response = NULL;

        cert_free(tsp_cert);
        tsp_cert = NULL;

        ba_free(tsp_storage_body);
        tsp_storage_body = NULL;

        pkcs12_free(tsp_storage);
        tsp_storage = NULL;

        ba_free(encoded);
        encoded = NULL;
    }

    ASN_FREE(get_INTEGER_desc(), serial_number);
}

/** Генерация сертификата OCSP-сервера. */
void generate_ocsp_certificate(void)
{
    int i;
    struct tm *timeinfo = NULL;
    time_t not_before;
    time_t not_after;

    ByteArray *encoded = NULL;
    Pkcs12Ctx *subject_storage = NULL;
    ByteArray *issuer_key = NULL;
    ByteArray *subject_storage_body = NULL;

    CertificationRequest_t *subject_cert_request = NULL;
    Certificate_t *subject_cert = NULL;
    Certificate_t *issuer_cert = NULL;

    Extensions_t *extensions = NULL;
    SubjectPublicKeyInfo_t *subject_spki = NULL;

    SignAdapter *subject_sa = NULL;
    DigestAdapter *subject_da = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;

    /* Серийный номер сертификата. */
    const unsigned char serial[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x12, 0xA8, 0x6D, 0x18, 0xDB, 0xC8, 0xB0, 0x4C
    };

    char *res_folder;

    /* Информация о получателе сертификата. */
    const char subject[] =
            "{O=Test}"
            "{OU=ЦСК}"
            "{CN=OCSP-ЦСК Test}"
            "{SN=UA-123456789-4312}"
            "{C=UA}"
            "{L=Днiпропетровськ}"
            "{ST=Дніпропетровська}";

    /* UTC time 25.01.23 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        tprintf("        - Генерация ключевой пары (%s).\n", res_folder);
        generate_dstu_keypair(dstu_params[i], cipher_params, &subject_storage);
        IS_NULL(subject_storage);

        EXECUTE(pkcs12_get_sign_adapter(subject_storage, &subject_sa));
        IS_NULL(subject_sa);

        EXECUTE(subject_sa->get_pub_key(subject_sa, &subject_spki));
        EXECUTE(digest_adapter_init_by_aid(&subject_spki->algorithm, &subject_da));
        IS_NULL(subject_da);

        tprintf("        - Генерация запроса на сертификат (%s).\n", res_folder);

        EXECUTE(ecert_request_alloc(subject_sa, &cert_request_eng));
        EXECUTE(ecert_request_set_subj_name(cert_request_eng, subject));
        EXECUTE(ecert_request_generate(cert_request_eng, &subject_cert_request));
        IS_NULL(subject_cert_request);

        /* Запись cert_request. */
        EXECUTE(creq_encode(subject_cert_request, &encoded));
        save_ba_to_file(encoded, res_folder, "ocsp/request.csr");
        ba_free(encoded);
        encoded = NULL;

        /* Чтение закрытого ключа и сертификата подписчика. */
        load_ba_from_file(&issuer_key, res_folder, "root/private.key");
        load_certificate(res_folder, "root/certificate.cer", &issuer_cert);

        extgen_ocsp(subject_spki, subject_da, &issuer_cert->tbsCertificate.validity, issuer_cert, &extensions);
        IS_NULL(extensions);


        tprintf("        - Создание сертификата для OCSP-сервера (%s).\n", res_folder);
        generate_cert_core(subject_cert_request, &not_before, &not_after, serial, extensions, issuer_key,
                issuer_cert, &subject_cert);
        IS_NULL(subject_cert);


        /* Запись сформированного сертификата. */
        EXECUTE(cert_encode(subject_cert, &encoded));
        save_ba_to_file(encoded, res_folder, "ocsp/certificate.cer");

        const ByteArray *certs[2] = {NULL, NULL};
        certs[0] = encoded;
        certs[1] = NULL;
        EXECUTE(pkcs12_set_certificates(subject_storage, certs));


        pkcs12_encode(subject_storage, &subject_storage_body);
        save_ba_to_file(subject_storage_body, res_folder, "ocsp/private.key");

        ba_free(encoded);
        encoded = NULL;
        ba_free(issuer_key);
        issuer_key = NULL;
        pkcs12_free(subject_storage);
        subject_storage = NULL;

        exts_free(extensions);
        extensions = NULL;
        spki_free(subject_spki);
        subject_spki = NULL;
        ecert_request_free(cert_request_eng);
        cert_request_eng = NULL;

        digest_adapter_free(subject_da);
        subject_da = NULL;
        sign_adapter_free(subject_sa);
        subject_sa = NULL;

        cert_free(issuer_cert);
        issuer_cert = NULL;
        cert_free(subject_cert);
        subject_cert = NULL;
        creq_free(subject_cert_request);
        subject_cert_request = NULL;

        ba_free(subject_storage_body);
        subject_storage_body = NULL;
    }
}

/** Генерация запроса OCSP. */
void generate_ocsp_request(void)
{
    int i;
    OCSPRequest_t *ocsp_request = NULL;
    Certificate_t *ocsp_cert = NULL;
    Certificate_t *user_cert = NULL;
    Certificate_t *root_cert = NULL;

    ByteArray *buffer = NULL;
    ByteArray *user_storage_body = NULL;
    Pkcs12Ctx *user_storage = NULL;

    int timeout = 2;
    bool has_nonce = true;

    char *res_folder;

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        load_certificate(res_folder, "root/certificate.cer", &root_cert);
        load_certificate(res_folder, "userfiz/certificate.cer", &user_cert);
        load_certificate(res_folder, "ocsp/certificate.cer", &ocsp_cert);
        load_ba_from_file(&user_storage_body, res_folder, "userfiz/private.key");

        EXECUTE(pkcs12_decode(NULL, user_storage_body, DEFAULT_STORAGE_PASSWORD, &user_storage));
        EXECUTE(pkcs12_select_key(user_storage, NULL, DEFAULT_KEY_PASSWORD));

        tprintf("        - Генерация OCSP-запроса (%s).\n", res_folder);
        create_ocsp_request(root_cert, user_cert, ocsp_cert, user_storage, timeout, has_nonce, &ocsp_request);
        IS_NULL(ocsp_request);

        EXECUTE(ocspreq_encode(ocsp_request, &buffer));
        save_ba_to_file(buffer, res_folder, "ocsp/ocsprequest.der");

        cert_free(root_cert);
        root_cert = NULL;

        cert_free(user_cert);
        user_cert = NULL;

        cert_free(ocsp_cert);
        ocsp_cert = NULL;

        ocspreq_free(ocsp_request);
        ocsp_request = NULL;

        ba_free(user_storage_body);
        user_storage_body = NULL;

        ba_free(buffer);
        buffer = NULL;

        pkcs12_free(user_storage);
        user_storage = NULL;
    }
}

/** Генерация ответа OCSP. */
void generate_ocsp_response(void)
{
    int i;
    OCSPRequest_t *ocsp_request = NULL;
    OCSPResponse_t *ocsp_response = NULL;

    Certificate_t *ocsp_cert = NULL;
    Certificate_t *root_cert = NULL;
    CertificateList_t *crl_full = NULL;
    CertificateList_t *crl_delta = NULL;
    CertificateLists_t *crls = NULL;

    ByteArray *ocsp_stprage_body;
    Pkcs12Ctx *ocsp_storage = NULL;
    ByteArray *encoded = NULL;
    ByteArray *buffer = NULL;

    struct tm *timeinfo = NULL;
    time_t current_time;
    int ret = RET_OK;
    char *res_folder;

    /* UTC time 25.01.13 22:00:00. */
    timeinfo = calloc(sizeof(struct tm), 1);
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    current_time = mktime(timeinfo);
    free(timeinfo);

    for (i = 0; i < dstu_params_count; i++) {
        res_folder = (char *) dstu_params_name_map[i];

        load_ba_from_file(&encoded, res_folder, "ocsp/ocsprequest.der");
        ocsp_request = ocspreq_alloc();
        IS_NULL(ocsp_request);
        EXECUTE(ocspreq_decode(ocsp_request, encoded));

        ba_free(encoded);
        encoded = NULL;

        load_ba_from_file(&encoded, res_folder, "root/certificate.cer");
        root_cert = cert_alloc();
        IS_NULL(root_cert);
        EXECUTE(cert_decode(root_cert, encoded));

        ba_free(encoded);
        encoded = NULL;

        load_ba_from_file(&encoded, res_folder, "crl/full.crl");
        crl_full = crl_alloc();
        IS_NULL(crl_full);
        EXECUTE(crl_decode(crl_full, encoded));

        ba_free(encoded);
        encoded = NULL;

        load_ba_from_file(&encoded, res_folder, "crl/delta.crl");
        crl_delta = crl_alloc();
        IS_NULL(crl_delta);
        EXECUTE(crl_decode(crl_delta, encoded));

        ba_free(encoded);
        encoded = NULL;

        ASN_ALLOC(crls);
        ASN_SET_ADD(crls, crl_full);
        ASN_SET_ADD(crls, crl_delta);

        load_ba_from_file(&encoded, res_folder, "ocsp/certificate.cer");
        ocsp_cert = cert_alloc();
        IS_NULL(ocsp_cert);
        EXECUTE(cert_decode(ocsp_cert, encoded));

        load_ba_from_file(&ocsp_stprage_body, res_folder, "ocsp/private.key");

        EXECUTE(pkcs12_decode(NULL, ocsp_stprage_body, DEFAULT_STORAGE_PASSWORD, &ocsp_storage));
        EXECUTE(pkcs12_select_key(ocsp_storage, NULL, DEFAULT_KEY_PASSWORD));

        tprintf("        - Генерация OCSP-ответа (%s).\n", res_folder);
        create_ocsp_response(ocsp_request, root_cert, ocsp_cert, crls, ocsp_storage, current_time, &ocsp_response);
        IS_NULL(ocsp_response);

        EXECUTE(ocspresp_encode(ocsp_response, &buffer));
        save_ba_to_file(buffer, res_folder, "ocsp/response.der");

        cert_free(root_cert);
        root_cert = NULL;

        cert_free(ocsp_cert);
        ocsp_cert = NULL;

        ASN_FREE(get_CertificateLists_desc(), crls);
        crls = NULL;

        ocspreq_free(ocsp_request);
        ocsp_request = NULL;

        ocspresp_free(ocsp_response);
        ocsp_response = NULL;

        ba_free(ocsp_stprage_body);
        ocsp_stprage_body = NULL;

        ba_free(encoded);
        encoded = NULL;

        ba_free(buffer);
        buffer = NULL;

        pkcs12_free(ocsp_storage);
        ocsp_storage = NULL;
    }

cleanup:

    return;
}

int main(void)
{
    tprintf("\n\n     ========== Инициализация криптографических параметров ДСТУ 4145-2002 ==========\n\n");

    dstu4145_cache_init_all_std_params();

    dstu4145_init_all_std_params();
    gost3411_init_std_params();

    tprintf("\n\n     ========== Генерация корневых самоподписанных серитификатов ==========\n\n");

    generate_root_certificate();

    tprintf("\n\n     ========== Генерация пользовательских сертификатов ==========\n\n");

    generate_user_fiz_certificate();
    generate_user_ur_certificate();

    tprintf("\n\n     ========== Генерация списков отозванных сертификатов ==========\n\n");

    generate_crl_container();

    tprintf("\n\n     ========== Генерация сертификатов для TSP сервера ==========\n\n");

    generate_tsp_certificate();
    generate_tsp_request();
    generate_tsp_response();

    tprintf("\n\n     ========== Генерация сертификатов для OCSP сервера ==========\n\n");

    generate_ocsp_certificate();
    generate_ocsp_request();
    generate_ocsp_response();

    tprintf("\n\n     ========== Генерация контейнеров подписи ==========\n\n");

    generate_signed_data_container();

    tprintf("\n\n     ========== Генерация контейнеров защищенных данных\n"
            "                с применением статического алгоритма согласования ключей ==========\n\n");

    generate_enveloped_data_static();

    tprintf("\n\n     ========== Генерация контейнеров защищенных данных\n"
            "                с применением динамического алгоритма согласования ключей ==========\n\n");

    generate_enveloped_data_dynamic();

    dstu4145_free_all_std_params();
    gost3411_free_std_params();

    crypto_cache_free();
    stacktrace_finalize();

    tprintf("\n Total errors: %d\n\n", error_count);

    return 0;
}

