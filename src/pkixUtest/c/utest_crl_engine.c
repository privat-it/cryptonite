/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "crl_engine.h"
#include "cryptonite_manager.h"
#include "cert.h"
#include "exts.h"
#include "ext.h"
#include "crl.h"
#include "pkix_errors.h"

static void test_ecrl_generate_full(void)
{
    ByteArray *private_key = NULL;
    ByteArray *cert_ba = NULL;
    ByteArray *crl_ba = NULL;
    ByteArray *delta_crl_ba = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    Extensions_t *extensions = exts_alloc();
    Extension_t *ext = NULL;
    CrlEngine *crl_engine = NULL;
    CertificateList_t *crl = NULL;
    CertificateList_t *prev_crl = crl_alloc();
    CertificateList_t *delta_crl = crl_alloc();
    const char *crl_distr[] = {"http://ca.ua/crls/full.crl"};
    const char templ_name[] = "crl_full_templ";
    char  *act_templ_name = NULL;
    const char templ_descr[] = "description";
    char *act_templ_descr = NULL;
    CRLType type;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &cert_ba));
    ASSERT_RET_OK(cert_decode(cert, cert_ba));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/full.crl", &crl_ba));
    ASSERT_RET_OK(crl_decode(prev_crl, crl_ba));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET_OK(ext_create_crl_distr_points(true, crl_distr, 1, &ext));
    ASSERT_RET_OK(exts_add_extension(extensions, ext));

    ASSERT_RET_OK(ecrl_alloc(prev_crl, sa, va, extensions, templ_name, CRL_FULL, templ_descr, &crl_engine));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/delta.crl", &delta_crl_ba));
    ASSERT_RET_OK(crl_decode(delta_crl, delta_crl_ba));
    ASSERT_RET_OK(ecrl_merge_delta(crl_engine, delta_crl));

    ASSERT_RET_OK(ecrl_get_template_name(crl_engine, &act_templ_name));
    ASSERT_TRUE(strcmp(templ_name, act_templ_name) == 0);

    ASSERT_RET_OK(ecrl_get_type(crl_engine, &type));
    ASSERT_TRUE(type == CRL_FULL);

    ASSERT_RET_OK(ecrl_get_description(crl_engine, &act_templ_descr));
    ASSERT_TRUE(strcmp(templ_descr, act_templ_descr) == 0);

    ASSERT_RET_OK(ecrl_generate(crl_engine, &crl));
    ASSERT_NOT_NULL(crl);

cleanup:

    free(act_templ_descr);
    free(act_templ_name);
    BA_FREE(private_key, cert_ba, crl_ba, delta_crl_ba);
    exts_free(extensions);
    ext_free(ext);
    ecrl_free(crl_engine);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    cert_free(cert);
    crl_free(crl);
    crl_free(prev_crl);
    crl_free(delta_crl);
}

static void test_ecrl_generate_delta(void)
{
    ByteArray *private_key = NULL;
    ByteArray *cert_ba = NULL;
    ByteArray *revoked_cert_ba = NULL;
    ByteArray *crl_ba = NULL;
    ByteArray *full_crl_ba = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *revoked_cert = cert_alloc();
    CrlEngine *crl_engine = NULL;
    CRLReason_t *reason = NULL;
    CertificateList_t *crl = NULL;
    CertificateList_t *prev_crl = crl_alloc();
    CertificateList_t *full_crl = crl_alloc();
    const char templ_name[] = "crl_delta_templ";
    const char templ_descr[] = "description";
    struct tm *timeinfo = NULL;
    time_t revoke_time;

    /* UTC time 26.01.13 22:00:00. */
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

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &cert_ba));
    ASSERT_RET_OK(cert_decode(cert, cert_ba));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/delta.crl", &crl_ba));
    ASSERT_RET_OK(crl_decode(prev_crl, crl_ba));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET_OK(ecrl_alloc(prev_crl, sa, va, NULL, templ_name, CRL_DELTA, templ_descr, &crl_engine));

    ASSERT_RET_OK(asn_create_integer_from_long(CRLReason_aACompromise, &reason));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_certificate.cer",
            &revoked_cert_ba));
    ASSERT_RET_OK(cert_decode(revoked_cert, revoked_cert_ba));

    ASSERT_RET_OK(ecrl_add_revoked_cert(crl_engine, revoked_cert, reason, &revoke_time));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/delta.crl", &full_crl_ba));
    ASSERT_RET_OK(crl_decode(full_crl, full_crl_ba));
    ASSERT_RET(RET_PKIX_CRL_CANT_MERGE, ecrl_merge_delta(crl_engine, full_crl));

    ASSERT_RET_OK(ecrl_generate(crl_engine, &crl));
    ASSERT_NOT_NULL(crl);

cleanup:

    ASN_FREE(&CRLReason_desc, reason);
    BA_FREE(private_key, cert_ba, crl_ba, revoked_cert_ba, full_crl_ba);
    ecrl_free(crl_engine);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    cert_free(cert);
    cert_free(revoked_cert);
    crl_free(crl);
    crl_free(prev_crl);
    crl_free(full_crl);
}

static void test_ecrl_generate_next_update(void)
{
    ByteArray *private_key = NULL;
    ByteArray *cert_ba = NULL;
    ByteArray *crl_ba = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    CrlEngine *crl_engine = NULL;
    CertificateList_t *crl = NULL;
    CertificateList_t *prev_crl = crl_alloc();
    const char templ_name[] = "crl_full_templ";
    const char templ_descr[] = "description";
    struct tm *timeinfo = NULL;
    time_t next_update;

    /* UTC time 26.11.16 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 116;
    timeinfo->tm_mon  = 10;
    timeinfo->tm_mday = 26;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    next_update = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &cert_ba));
    ASSERT_RET_OK(cert_decode(cert, cert_ba));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/full.crl", &crl_ba));
    ASSERT_RET_OK(crl_decode(prev_crl, crl_ba));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET_OK(ecrl_alloc(prev_crl, sa, va, NULL, templ_name, CRL_FULL, templ_descr, &crl_engine));

    ASSERT_RET_OK(ecrl_generate_next_update(crl_engine, &next_update, &crl));
    ASSERT_NOT_NULL(crl);

cleanup:

    BA_FREE(private_key, cert_ba, crl_ba);
    ecrl_free(crl_engine);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    cert_free(cert);
    crl_free(crl);
    crl_free(prev_crl);
}

static void test_ecrl_generate_diff_next_update(void)
{
    ByteArray *private_key = NULL;
    ByteArray *cert_ba = NULL;
    ByteArray *crl_ba = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    CrlEngine *crl_engine = NULL;
    CertificateList_t *crl = NULL;
    CertificateList_t *prev_crl = crl_alloc();
    const char templ_name[] = "crl_full_templ";
    const char templ_descr[] = "description";

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &cert_ba));
    ASSERT_RET_OK(cert_decode(cert, cert_ba));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/full.crl", &crl_ba));
    ASSERT_RET_OK(crl_decode(prev_crl, crl_ba));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET_OK(ecrl_alloc(prev_crl, sa, va, NULL, templ_name, CRL_FULL, templ_descr, &crl_engine));

    ASSERT_RET_OK(ecrl_generate_diff_next_update(crl_engine, 60 * 60 * 24 * 7, &crl));
    ASSERT_NOT_NULL(crl);

cleanup:

    BA_FREE(private_key, cert_ba, crl_ba);
    ecrl_free(crl_engine);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    cert_free(cert);
    crl_free(crl);
    crl_free(prev_crl);
}


void utest_crl_engine(void)
{
    PR("%s\n", __FILE__);

    test_ecrl_generate_full();
    test_ecrl_generate_delta();
    test_ecrl_generate_next_update();
    test_ecrl_generate_diff_next_update();
}
