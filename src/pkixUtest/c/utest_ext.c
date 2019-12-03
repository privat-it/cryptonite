/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <time.h>

#include "utest.h"
#include "cert.h"
#include "cert_engine.h"
#include "asn1_utils.h"
#include "aid.h"
#include "cryptonite_manager.h"
#include "certificate_request_engine.h"
#include "certification_request.h"
#include "rs.h"
#include "crl.h"
#include "spki.h"
#include "ext.h"
#include "exts.h"
#include "pkix_errors.h"

static void test_extensions_generate(void)
{
    Extension_t *ext = NULL;
    Extension_t *req_ext = NULL;

    CRLReason_t *reason = NULL;
    CertificationRequest_t *cert_request = NULL;
    Certificate_t *cert = cert_alloc();
    SubjectPublicKeyInfo_t *spki =  spki_alloc();
    BasicConstraints_t *bc = NULL;
    SignAdapter *sa = NULL;
    CertificateRequestEngine *req_ctx = NULL;

    ByteArray *rnd_bts = ba_alloc_from_le_hex_string("0123456789ABCDEF");
    ByteArray *buffer = NULL;
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *spki_ba =
            ba_alloc_from_le_hex_string("3076301006072A8648CE3D020106052B810400220362000492383026BF1F7DD144817BE48B7D0B90B6305"
                    "F15EDF02C0A5958ABDF5372337A28228D09457BCDAFEECD3A960F86DA70EC4435034B7A25737735FF7174"
                    "423D06A0839AC58B5DFAB966B4C6A9F515333E6D8A562F321C71E02990DD03F275DF70");
    ByteArray *ext_value = ba_alloc_from_le_hex_string("300D300B06092A8624020101010201");
    ByteArray *basic_constr = ba_alloc_from_le_hex_string("30060101FF020102");
    ByteArray *subj_dir_attr =
            ba_alloc_from_le_hex_string("304F301A060C2A8624020101010B01040201310A13083131313131313131301C060C2A8624020101010B01040101310C130A313131313131313131313013060C2A8624020101010B010407013103130130");
    ByteArray *subj_alt_name =
            ba_alloc_from_le_hex_string("3081A3A056060C2B0601040181974601010402A0460C4430343635352C20D0BC2E20D09AD0B8D197D0B22C20D09BD18CD0B2D196D0B2D181D18CD0BAD0B020D0BFD0BBD0BED189D0B02C20D0B1D183D0B4D0B8D0BDD0BED0BA2038A022060C2B0601040181974601010401A0120C102B333830283434292032343830303130820E6163736B6964642E676F762E75618115696E666F726D406163736B6964642E676F762E7561");
    ByteArray *exp_ext =
            ba_alloc_from_le_hex_string("3081A3A056060C2B0601040181974601010402A0460C4430343635352C20D0BC2E20D09AD0B8D197D0B22C20D09BD18CD0B2D196D0B2D181D18CD0BAD0B020D0BFD0BBD0BED189D0B02C20D0B1D183D0B4D0B8D0BDD0BED0BA2038A022060C2B0601040181974601010401A0120C102B333830283434292032343830303130820E6163736B6964642E676F762E75618115696E666F726D406163736B6964642E676F762E7561");

    CertificateList_t *crl = crl_alloc();
    time_t this_update;

    ByteArray *crl_number = ba_alloc_from_le_hex_string("4461");

    OBJECT_IDENTIFIER_t *extkey_usage = NULL;

    long cert_policy_oid[] = {1, 2, 804, 2, 1, 1, 1, 2, 2};
    OidNumbers cert_policy1 = {cert_policy_oid, 9};
    OidNumbers *cert_policy = &cert_policy1;

    QCStatement_t *qc_statement = NULL;
    QCStatement_t **qc_statements = malloc(2 * sizeof(QCStatement_t *));

    ASSERT_NOT_NULL(qc_statements);

    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};
    const char *fresh_crl[] = {"http://ca.ua/crls/delta.crl"};
    char distr_url[] = "http://czo.gov.ua/download/crls/CZO-Full.crl";

    long auth_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 1};
    OidNumbers auth_info1 = {auth_info_oid, 9};
    OidNumbers *auth_info = &auth_info1;
    const char *auth_uri[] = {"http://ca.ua/ocsp/"};

    long subj_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 3};
    OidNumbers subj_info1 = {subj_info_oid, 9};
    OidNumbers *subj_info = &subj_info1;
    const char *subj_uri[] = {"http://ca.ua/time-stamping/"};

    long ext_oid1[] = {1, 3, 6, 1, 5, 5, 7, 1, 3};
    OidNumbers ext_oid2 = {ext_oid1, 9};
    OidNumbers *ext_oid = &ext_oid2;

    long subj_dir_attr_oid1[] = {2, 5, 29, 9};
    OidNumbers subj_dir_attr_oid2 = {subj_dir_attr_oid1, 4};
    OidNumbers *subj_dir_attr_oid = &subj_dir_attr_oid2;

    long subj_alt_name_oid1[] = {2, 5, 29, 17};
    OidNumbers subj_alt_name_oid2 = {subj_alt_name_oid1, 4};
    OidNumbers *subj_alt_name_oid = &subj_alt_name_oid2;

    ByteArray *crl_sn = ba_alloc_from_le_hex_string("0123");
    struct tm *timeinfo = NULL;
    time_t revoke_time;

    ASSERT_RET_OK(asn_create_oid_from_text("1.3.6.1.5.5.7.3.9", &extkey_usage));

    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    revoke_time = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ext_create_key_usage(true, KEY_USAGE_KEY_CERTSIGN | KEY_USAGE_CRL_SIGN, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_cert_policies(true, &cert_policy, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_ASN_ALLOC(bc);
    ASSERT_RET_OK(asn_decode(&BasicConstraints_desc, bc, basic_constr->buf, basic_constr->len));

    ASSERT_RET_OK(ext_create_basic_constraints(true, bc, true, 0, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_basic_constraints(true, NULL, true, 0, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_qc_statement_compliance(&qc_statement));
    qc_statements[0] = qc_statement;
    ASSERT_RET_OK(ext_create_qc_statement_limit_value("UAH", 1000, 0, &qc_statement));
    qc_statements[1] = qc_statement;

    ASSERT_RET_OK(ext_create_qc_statements(true, qc_statements, 2, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_crl_distr_points(true, crl_distr, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_auth_info_access(false, &auth_info, auth_uri, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_nonce(false, rnd_bts, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_invalidity_date(false, &revoke_time, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/CZO-Full.crl", &buffer));
    ASSERT_RET_OK(crl_decode(crl, buffer));
    ASSERT_RET_OK(crl_get_this_update(crl, &this_update));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ext_create_crl_id(false, distr_url, crl_number, &this_update, &ext));
    ext_free(ext);
    ext = NULL;
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ext_create_crl_number(false, crl_sn, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(asn_create_integer_from_long(CRLReason_keyCompromise, &reason));
    ASSERT_RET_OK(ext_create_crl_reason(false, reason, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_delta_crl_indicator(true, crl_sn, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_delta_crl_indicator(true, crl_sn, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_ext_key_usage(true, &extkey_usage, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ext_create_auth_key_id_from_cert(false, cert, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_private_key_usage(false, &cert->tbsCertificate.validity, NULL, NULL, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_subj_info_access(false, &subj_info, subj_uri, 1, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(spki_decode(spki, spki_ba));
    ASSERT_RET_OK(ext_create_auth_key_id_from_spki(false, spki, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(ext_create_any(true, ext_oid, ext_value, &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(ecert_request_alloc(sa, &req_ctx));

    //subj_dir_attr
    ASSERT_RET_OK(ext_create_any(false, subj_dir_attr_oid, subj_dir_attr, &req_ext));
    ASSERT_RET_OK(ecert_request_add_ext(req_ctx, req_ext));
    ext_free(req_ext);
    req_ext = NULL;

    //subj_alt_name
    ASSERT_RET_OK(ext_create_any(false, subj_alt_name_oid, subj_alt_name, &req_ext));
    ASSERT_RET_OK(ecert_request_add_ext(req_ctx, req_ext));
    ext_free(req_ext);
    req_ext = NULL;

    ASSERT_RET_OK(ecert_request_generate(req_ctx, &cert_request));
    ASSERT_RET_OK(creq_encode(cert_request, &buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(creq_get_ext_by_oid(cert_request,
            oids_get_oid_numbers_by_id(OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID), &ext));
    ext_free(ext);
    ext = NULL;

    ASSERT_RET_OK(creq_get_ext_by_oid(cert_request, oids_get_oid_numbers_by_id(OID_SUBJECT_ALT_NAME_EXTENSION_ID), &ext));

    ASSERT_RET_OK(ext_get_value(ext, &buffer));
    ASSERT_EQUALS_BA(exp_ext, buffer);

    ext_free(ext);
    ext = NULL;

cleanup:

    BA_FREE(rnd_bts, private_key, spki_ba, ext_value, basic_constr, crl_number,
            subj_dir_attr, subj_alt_name, crl_sn, exp_ext, buffer);

    ASN_FREE(&OBJECT_IDENTIFIER_desc, extkey_usage);
    ASN_FREE(&CRLReason_desc, reason);
    ASN_FREE(&BasicConstraints_desc, bc);

    ASN_FREE(&QCStatement_desc, qc_statements[0]);
    ASN_FREE(&QCStatement_desc, qc_statements[1]);
    free(qc_statements);

    creq_free(cert_request);
    cert_free(cert);
    spki_free(spki);
    crl_free(crl);

    sign_adapter_free(sa);
    ecert_request_free(req_ctx);
}

static void test_exts_get_ext(void)
{
    Extensions_t *exts = exts_alloc();
    OidNumbers *oid = NULL;
    Extension_t *ext = NULL;
    ByteArray *ext_ba = NULL;

    ASSERT_NOT_NULL(oid = oids_get_oid_numbers_by_str("1.1.1"));
    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, exts_get_ext_by_oid(exts, oid, &ext));
    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, exts_get_ext_value_by_oid(exts, oid, &ext_ba));

cleanup:

    ba_free(ext_ba);
    exts_free(exts);
    oids_oid_numbers_free(oid);
    ext_free(ext);
}

static void test_ext_create_auth_info_access(void)
{
    Extension_t *ext = NULL;
    long auth_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 1};
    OidNumbers auth_info1 = {auth_info_oid, 9};
    OidNumbers *auth_info = &auth_info1;
    const char *auth_uri[] = {NULL};

    ASSERT_RET(RET_INVALID_PARAM, ext_create_auth_info_access(false, &auth_info, auth_uri, 1, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_ext_key_usage(void)
{
    Extension_t *ext = NULL;
    OBJECT_IDENTIFIER_t **key_usage = malloc(2 * sizeof(OBJECT_IDENTIFIER_t *));
    ASSERT_NOT_NULL(key_usage);

    key_usage[0] = NULL;
    key_usage[1] = NULL;


    ASSERT_RET(RET_INVALID_PARAM, ext_create_ext_key_usage(true, key_usage, 2, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
    free(key_usage);
}

static void test_ext_create_freshest_crl(void)
{
    Extension_t *ext = NULL;
    const char *fresh_crl[] = {NULL};

    ASSERT_RET(RET_INVALID_PARAM, ext_create_freshest_crl(false, fresh_crl, 1, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_crl_distr_points(void)
{
    Extension_t *ext = NULL;
    const char *crl_distr[] = {NULL};

    ASSERT_RET(RET_INVALID_PARAM, ext_create_crl_distr_points(true, crl_distr, 1, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_subj_info_access(void)
{
    Extension_t *ext = NULL;
    const char *subj_uri[] = {NULL};
    long subj_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 3};
    OidNumbers subj_info1 = {subj_info_oid, 9};
    OidNumbers *subj_info = &subj_info1;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_info_access(false, &subj_info, subj_uri, 1, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_cert_policies(void)
{
    Extension_t *ext = NULL;
    OidNumbers cert_policy1 = {NULL, 0};
    OidNumbers *cert_policy = &cert_policy1;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_cert_policies(true, &cert_policy, 1, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_subj_alt_name_directly(void)
{
    Extension_t *ext = NULL;
    enum GeneralName_PR types[] = {GeneralName_PR_NOTHING, GeneralName_PR_otherName};
    char dns[] = "ca.ua";
    char email[] = "info@ca.ua";
    const char *alt_names[2];
    alt_names[0] = dns;
    alt_names[1] = email;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_alt_name_directly(false, NULL, alt_names, 2, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_alt_name_directly(false, types, NULL, 2, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_alt_name_directly(false, types, alt_names, 0, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET(RET_PKIX_UNSUPPORTED_PKIX_OBJ, ext_create_subj_alt_name_directly(false, types, alt_names, 2, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_private_key_usage(void)
{
    Extension_t *ext = NULL;
    time_t not_before;
    time_t not_after;
    struct tm *timeinfo = NULL;

    /* UTC time 26.01.23 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
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
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_before = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET(RET_INVALID_PARAM, ext_create_private_key_usage(false, NULL, NULL, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET(RET_INVALID_PARAM, ext_create_private_key_usage(false, NULL, NULL, &not_after, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET(RET_INVALID_PARAM, ext_create_private_key_usage(false, NULL, &not_before, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

    ASSERT_RET_OK(ext_create_private_key_usage(false, NULL, &not_before, &not_after, &ext));
    ASSERT_NOT_NULL(ext);

cleanup:

    ext_free(ext);
}

static void test_ext_create_subj_dir_attr_directly(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_dir_attr_directly(true, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_any(void)
{
    Extension_t *ext = NULL;
    long subj_info_oid[] = {1, 3, 6, 1, 5, 5, 7, 48, 3};
    OidNumbers subj_info1 = {subj_info_oid, 9};
    OidNumbers *subj_info = &subj_info1;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_any(true, subj_info, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_nonce(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_nonce(false, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_subj_key_id(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_subj_key_id(false, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_auth_key_id_from_cert(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_auth_key_id_from_cert(false, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_auth_key_id_from_spki(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_auth_key_id_from_spki(false, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_crl_reason(void)
{
    Extension_t *ext = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ext_create_crl_reason(false, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
}

static void test_ext_create_private_key_usage_2(void)
{
    Extension_t *ext = NULL;
    Validity_t *validity = NULL;
    PKIXTime_t *pkix_time = NULL;
    struct tm tm_time;
    UTCTime_t *utcTime = NULL;
    time_t not_after;
    struct tm *timeinfo = NULL;

    /* UTC time 26.01.23 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 123;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    not_after = mktime(timeinfo);
    free(timeinfo);

    ASSERT_ASN_ALLOC(validity);
    ASSERT_ASN_ALLOC(pkix_time);

    memcpy(&tm_time, localtime(&not_after), sizeof(tm_time));
    pkix_time->present = PKIXTime_PR_utcTime;
    utcTime = asn_time2UT(NULL, &tm_time, true);

    ASSERT_RET_OK(asn_copy(&UTCTime_desc, utcTime, &pkix_time->choice.utcTime));
    ASSERT_RET_OK(asn_copy(&PKIXTime_desc, pkix_time, &validity->notAfter));
    validity->notAfter.present = PKIXTime_PR_NOTHING;

    ASSERT_RET(RET_PKIX_UNSUPPORTED_PKIX_TIME, ext_create_private_key_usage(false, validity, NULL, NULL, &ext));
    ASSERT_TRUE(ext == NULL);

cleanup:

    ext_free(ext);
    ASN_FREE(&Validity_desc, validity);
    ASN_FREE(&PKIXTime_desc, pkix_time);
    ASN_FREE(&UTCTime_desc, utcTime);
}

void utest_ext(void)
{
    PR("%s\n", __FILE__);

    test_extensions_generate();
    test_exts_get_ext();
    test_ext_create_auth_info_access();
    test_ext_ext_key_usage();
    test_ext_create_freshest_crl();
    test_ext_create_crl_distr_points();
    test_ext_create_subj_info_access();
    test_ext_create_cert_policies();
    test_ext_create_subj_alt_name_directly();
    test_ext_create_private_key_usage();
    test_ext_create_subj_dir_attr_directly();
    test_ext_create_any();
    test_ext_create_nonce();
    test_ext_create_subj_key_id();
    test_ext_create_auth_key_id_from_cert();
    test_ext_create_auth_key_id_from_spki();
    test_ext_create_crl_reason();
    test_ext_create_private_key_usage_2();
}
