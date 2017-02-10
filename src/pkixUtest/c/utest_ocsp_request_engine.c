/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "ocsp_request.h"
#include "ocsp_request_engine.h"
#include "cert.h"
#include "cryptonite_manager.h"
#include "asn1_utils.h"

static void test_eocspreq_generate(void)
{
    Certificate_t *root_cert = cert_alloc();
    Certificate_t *ocsp_cert = cert_alloc();
    Certificate_t *cert = cert_alloc();

    VerifyAdapter *root_va = NULL;
    VerifyAdapter *ocsp_va = NULL;
    VerifyAdapter *user_va = NULL;
    SignAdapter *sa = NULL;
    DigestAdapter *da = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;
    ByteArray *nonce = ba_alloc_by_len(20);
    ba_set(nonce, 0xaf);

    OcspRequestEngine *eocsp_request = NULL;
    OCSPRequest_t *request = NULL;

    bool has_sign;

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

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &user_va));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));

    ASSERT_RET_OK(eocspreq_alloc(true, root_va, ocsp_va, sa, da, &eocsp_request));
    ASSERT_RET_OK(eocspreq_add_cert(eocsp_request, cert));
    ASSERT_RET_OK(eocspreq_generate(eocsp_request, nonce, &request));

    ASSERT_RET_OK(ocspreq_has_sign(request, &has_sign));
    ASSERT_TRUE(has_sign == true);

    ASSERT_RET_OK(ocspreq_verify(request, user_va));

cleanup:

    BA_FREE(private_key, nonce);
    verify_adapter_free(root_va);
    verify_adapter_free(ocsp_va);
    verify_adapter_free(user_va);
    eocspreq_free(eocsp_request);
    cert_free(root_cert);
    cert_free(ocsp_cert);
    cert_free(cert);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    ocspreq_free(request);
}

static void test_eocspreq_generate_from_cert(void)
{
    Certificate_t *root_cert = cert_alloc();
    Certificate_t *cert = cert_alloc();
    OCSPRequest_t *request = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;

    bool has_sign;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_private_key_ba.dat",
            &private_key));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/root_certificate.cer", &buffer));
    ASSERT_RET_OK(cert_decode(root_cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(eocspreq_generate_from_cert(root_cert, cert, &request));

    ASSERT_RET_OK(ocspreq_has_sign(request, &has_sign));
    ASSERT_TRUE(has_sign == false);

cleanup:

    ba_free(private_key);
    cert_free(root_cert);
    cert_free(cert);
    ocspreq_free(request);
}

void utest_ocsp_request_engine(void)
{
    PR("%s\n", __FILE__);

    test_eocspreq_generate();
    test_eocspreq_generate_from_cert();
}


