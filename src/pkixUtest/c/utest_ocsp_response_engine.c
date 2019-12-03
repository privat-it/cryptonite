/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "ocsp_response.h"
#include "ocsp_request.h"
#include "ocsp_response_engine.h"
#include "ocsp_request_engine.h"
#include "cert.h"
#include "cryptonite_manager.h"
#include "crl.h"
#include "asn1_utils.h"

static void eocspreq_generate_for_revoked_cert(ByteArray *cert_sn, OCSPRequest_t **req)
{
    Certificate_t *root_cert = cert_alloc();
    Certificate_t *ocsp_cert = cert_alloc();
    Certificate_t *cert = cert_alloc();

    VerifyAdapter *root_va = NULL;
    VerifyAdapter *ocsp_va = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;

    OcspRequestEngine *eocsp_request = NULL;
    OCSPRequest_t *request = NULL;

    CertificateSerialNumber_t *csn = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_private_key_ba.dat",
            &private_key));

    ASSERT_RET_OK(digest_adapter_init_default(&da));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(ocsp_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(root_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(verify_adapter_init_by_cert(root_cert, &root_va));
    ASSERT_RET_OK(verify_adapter_init_by_cert(ocsp_cert, &ocsp_va));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));

    ASSERT_RET_OK(eocspreq_alloc(false, root_va, ocsp_va, sa, da, &eocsp_request));
    ASSERT_RET_OK(asn_create_integer_from_ba(cert_sn, &csn));
    ASSERT_RET_OK(eocspreq_add_sn(eocsp_request, csn));
    ASSERT_RET_OK(eocspreq_generate(eocsp_request, NULL, &request));
    *req = request;
    request = NULL;

cleanup:

    ba_free(private_key);
    verify_adapter_free(root_va);
    verify_adapter_free(ocsp_va);
    eocspreq_free(eocsp_request);
    cert_free(root_cert);
    cert_free(ocsp_cert);
    cert_free(cert);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    ocspreq_free(request);
    ASN_FREE(&CertificateSerialNumber_desc, csn);
}

static void test_eocspresp_generate(void)
{
    Certificate_t *root_cert = cert_alloc();
    Certificate_t *ocsp_cert = cert_alloc();
    Certificate_t *user_cert = cert_alloc();
    CertificateLists_t *crls = NULL;
    CertificateList_t *full_crl = crl_alloc();
    CertificateList_t *delta_crl = crl_alloc();

    VerifyAdapter *ocsp_va = NULL;
    VerifyAdapter *root_va = NULL;
    VerifyAdapter *req_va = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;

    OcspResponseEngine *eocsp_response = NULL;
    OCSPResponse_t *response = NULL;
    OCSPResponseStatus_t *status = NULL;
    long ocsp_status;
    OCSPRequest_t *ocsp_request = ocspreq_alloc();

    struct tm *timeinfo = NULL;
    time_t current_time;

    /* UTC time 25.01.13 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(sizeof(struct tm), 1));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    current_time = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_private_key_ba.dat",
            &private_key));

    ASSERT_RET_OK(digest_adapter_init_default(&da));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(root_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(verify_adapter_init_by_cert(root_cert, &root_va));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(ocsp_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, ocsp_cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(ocsp_cert, &ocsp_va));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/full.crl", &buffer));
    ASSERT_RET_OK(crl_decode(full_crl, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/delta.crl", &buffer));
    ASSERT_RET_OK(crl_decode(delta_crl, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_ASN_ALLOC(crls);
    ASN_SET_ADD(&crls->list, full_crl);
    ASN_SET_ADD(&crls->list, delta_crl);

    ASSERT_RET_OK(eocspresp_alloc(root_va, sa, crls, da, true, true, OCSP_RESPONSE_BY_HASH_KEY, &eocsp_response));
    eocspresp_set_sign_required(eocsp_response, true);
    ASSERT_RET_OK(eocspresp_set_crls(eocsp_response, crls));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_request.der", &buffer));
    ASSERT_RET_OK(ocspreq_decode(ocsp_request, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(user_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(verify_adapter_init_by_cert(user_cert, &req_va));

    ASSERT_RET_OK(eocspresp_generate(eocsp_response, ocsp_request, req_va, current_time, &response));
    ASSERT_RET_OK(ocspresp_verify(response, ocsp_va));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_successful);

cleanup:

    ba_free(private_key);

    verify_adapter_free(ocsp_va);
    verify_adapter_free(root_va);
    verify_adapter_free(req_va);
    digest_adapter_free(da);
    sign_adapter_free(sa);

    cert_free(root_cert);
    cert_free(ocsp_cert);
    cert_free(user_cert);

    eocspresp_free(eocsp_response);
    ocspresp_free(response);
    ocspreq_free(ocsp_request);

    ASN_FREE(&CertificateLists_desc, crls);
    ASN_FREE(&OCSPResponseStatus_desc, status);
}

static void test_eocspresp_generate_2(void)
{
    Certificate_t *root_cert = cert_alloc();
    Certificate_t *ocsp_cert = cert_alloc();
    Certificate_t *user_cert = cert_alloc();
    CertificateLists_t *crls = NULL;
    CertificateList_t *full_crl = crl_alloc();
    CertificateList_t *delta_crl = crl_alloc();

    VerifyAdapter *ocsp_va = NULL;
    VerifyAdapter *root_va = NULL;
    VerifyAdapter *req_va = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;

    OcspResponseEngine *eocsp_response = NULL;
    OCSPResponse_t *response = NULL;
    OCSPResponseStatus_t *status = NULL;
    long ocsp_status;
    OCSPRequest_t *ocsp_request = NULL;

    struct tm *timeinfo = NULL;
    time_t current_time;
    int timeout = 2;

    /* UTC time 25.01.13 22:00:00. */
    ASSERT_NOT_NULL(timeinfo = calloc(sizeof(struct tm), 1));
    timeinfo->tm_year = 113;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    current_time = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_private_key_ba.dat",
            &private_key));

    ASSERT_RET_OK(digest_adapter_init_default(&da));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(root_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(verify_adapter_init_by_cert(root_cert, &root_va));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/ocsp_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(ocsp_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, ocsp_cert, &sa));
    ASSERT_RET_OK(verify_adapter_init_by_cert(ocsp_cert, &ocsp_va));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/full.crl", &buffer));
    ASSERT_RET_OK(crl_decode(full_crl, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/delta.crl", &buffer));
    ASSERT_RET_OK(crl_decode(delta_crl, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_ASN_ALLOC(crls);
    ASN_SET_ADD(&crls->list, full_crl);
    ASN_SET_ADD(&crls->list, delta_crl);

    ASSERT_RET_OK(eocspresp_alloc(root_va, sa, crls, da, true, true, OCSP_RESPONSE_BY_NAME, &eocsp_response));
    eocspresp_set_sign_required(eocsp_response, true);
    ASSERT_RET_OK(eocspresp_set_crls(eocsp_response, crls));

    buffer = ba_alloc_from_str("3468");
    eocspreq_generate_for_revoked_cert(buffer , &ocsp_request);
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(user_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(verify_adapter_init_by_cert(user_cert, &req_va));

    ASSERT_RET_OK(eocspresp_generate(eocsp_response, ocsp_request, req_va, current_time, &response));
    ASSERT_RET_OK(ocspresp_verify(response, ocsp_va));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_successful);

    ASSERT_RET_OK(eocspreq_validate_resp(response, current_time, timeout));

cleanup:

    ba_free(private_key);

    verify_adapter_free(ocsp_va);
    verify_adapter_free(root_va);
    verify_adapter_free(req_va);
    digest_adapter_free(da);
    sign_adapter_free(sa);

    cert_free(root_cert);
    cert_free(ocsp_cert);
    cert_free(user_cert);

    eocspresp_free(eocsp_response);
    ocspresp_free(response);
    ocspreq_free(ocsp_request);

    ASN_FREE(&CertificateLists_desc, crls);
    ASN_FREE(&OCSPResponseStatus_desc, status);
}

static void test_eocspresp_generate_3(void)
{
    OCSPResponse_t *response = NULL;
    OCSPResponseStatus_t *status = NULL;
    long ocsp_status;

    ASSERT_RET_OK(eocspresp_form_malformed_req(&response));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_malformedRequest);
    ocspresp_free(response);
    ASN_FREE(&OCSPResponseStatus_desc, status);
    response = NULL;
    status = NULL;

    ASSERT_RET_OK(eocspresp_form_internal_error(&response));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_internalError);
    ocspresp_free(response);
    ASN_FREE(&OCSPResponseStatus_desc, status);
    response = NULL;
    status = NULL;

    ASSERT_RET_OK(eocspresp_form_try_later(&response));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_tryLater);
    ocspresp_free(response);
    ASN_FREE(&OCSPResponseStatus_desc, status);
    response = NULL;
    status = NULL;

    ASSERT_RET_OK(eocspresp_form_unauthorized(&response));

    ASSERT_RET_OK(ocspresp_get_status(response, &status));
    ASSERT_RET_OK(asn_INTEGER2long(status, &ocsp_status));
    ASSERT_TRUE(ocsp_status == OCSPResponseStatus_unauthorized);

cleanup:

    ocspresp_free(response);
    ASN_FREE(&OCSPResponseStatus_desc, status);
}

void utest_ocsp_response_engine(void)
{
    PR("%s\n", __FILE__);

    test_eocspresp_generate();
    test_eocspresp_generate_2();
    test_eocspresp_generate_3();
}


