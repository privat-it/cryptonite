/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pkcs5.h"
#include "test_utils.h"
#include "pkcs12.h"
#include "certificate_request_engine.h"
#include "certification_request.h"
#include "cryptonite_manager.h"
#include "pkix_utils.h"
#include "aid.h"
#include "pkix_errors.h"

void test_storage_gen_verify_cert_req(void)
{
    Pkcs12Ctx *storage = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    ByteArray *sign_ba = NULL;
    ByteArray *cert_ba = NULL;
    const ByteArray *certs[2] = {NULL};
    ByteArray *storage_ba = NULL;
    ByteArray *aid = ba_alloc_from_le_hex_string("301006072A8648CE3D020106052B81040022");
    CertificationRequest_t *cert_req = NULL;
    CertificateRequestEngine *cert_request_eng = NULL;
    DigestAlgorithmIdentifier_t *daid = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/storageUtest/resources/pkcs12_cert_cryptonite.crt", &cert_ba));
    ASSERT_RET_OK(pkcs12_create(KS_FILE_PKCS12_WITH_SHA384, "123456", 1024, &storage));
    ASSERT_RET_OK(pkcs12_generate_key(storage, aid));
    ASSERT_RET_OK(pkcs12_store_key(storage, "key", NULL, 1024));
    ASSERT_RET_OK(pkcs12_select_key(storage, "key", NULL));
    ASSERT_RET_OK(pkcs12_get_sign_adapter(storage, &sa));

    ASSERT_NOT_NULL(daid = calloc(1, sizeof(DigestAlgorithmIdentifier_t)));
    ASSERT_RET_OK(pkix_set_oid(oids_get_oid_numbers_by_id(OID_PKI_SHA224_ID), &daid->algorithm));
    ASSERT_RET_OK(sa->set_digest_alg(sa, daid));
    ASSERT_RET_OK(ecert_request_alloc(sa, &cert_request_eng));
    ASSERT_RET_OK(ecert_request_generate(cert_request_eng, &cert_req));

    ecert_request_free(cert_request_eng);
    cert_request_eng = NULL;

    certs[0] = cert_ba;

    sign_adapter_free(sa);
    sa = NULL;

    ASSERT_RET_OK(pkcs12_set_certificates(storage, certs));
    ASSERT_RET_OK(pkcs12_select_key(storage, "key", NULL));
    ASSERT_RET_OK(pkcs12_get_sign_adapter(storage, &sa));
    ASSERT_RET_OK(sa->sign_data(sa, cert_ba, &sign_ba));
    ASSERT_RET_OK(pkcs12_get_verify_adapter(storage, &va));
    ASSERT_RET_OK(va->set_digest_alg(va, daid));
    ASSERT_RET_OK(creq_verify(cert_req, va));
    ASSERT_RET_OK(pkcs12_change_password(storage, "123456", "12345"));

    ASSERT_RET_OK(pkcs12_encode(storage, &storage_ba));

    ba_free(sign_ba);
    sign_ba = NULL;

    pkcs12_free(storage);
    storage = NULL;

    sign_adapter_free(sa);
    sa = NULL;

    verify_adapter_free(va);
    va = NULL;

    creq_free(cert_req);
    cert_req = NULL;

    ASSERT_RET_OK(pkcs12_decode(NULL, storage_ba, "12345", &storage));
    ASSERT_RET_OK(pkcs12_select_key(storage, "key", NULL));
    ASSERT_RET_OK(pkcs12_get_sign_adapter(storage, &sa));

    ASSERT_RET_OK(ecert_request_alloc(sa, &cert_request_eng));
    ASSERT_RET_OK(ecert_request_generate(cert_request_eng, &cert_req));

cleanup:

    BA_FREE(cert_ba, sign_ba, aid, storage_ba);
    ecert_request_free(cert_request_eng);
    aid_free(daid);
    pkcs12_free(storage);
    sign_adapter_free(sa);
    verify_adapter_free(va);

    creq_free(cert_req);
}

void test_storage_decode(void)
{
    Pkcs12Ctx *st = NULL;
    Pkcs12Ctx *st1 = NULL;
    ByteArray *decode = NULL;

    ASSERT_RET_OK(pkcs12_create(KS_FILE_PKCS12_WITH_SHA224, "11111", 2048, &st));
    ASSERT_RET_OK(pkcs12_encode(st, &decode));
    ASSERT_RET_OK(pkcs12_decode(NULL, decode, "11111", &st1));

cleanup:

    pkcs12_free(st);
    pkcs12_free(st1);
    ba_free(decode);
}

void test_openssl_storage_decode(void)
{
    char password[] = "123456";
    ByteArray *storage_ba = NULL;
    ByteArray *encoded_storage = NULL;
    Pkcs12Ctx *st = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/storageUtest/resources/ossl_ecdsa_aes_256_cbc_storage_123456.p12", &storage_ba));

    ASSERT_RET_OK(pkcs12_decode(NULL, storage_ba, password, &st));
    ASSERT_RET_OK(pkcs12_encode(st, &encoded_storage));
    ASSERT_EQUALS_BA(storage_ba, encoded_storage);

cleanup:

    BA_FREE(storage_ba, encoded_storage);
    pkcs12_free(st);
}

void utest_pkcs12_ecdsa(void)
{
    PR("%s\n", __FILE__);

    test_storage_decode();
    test_openssl_storage_decode();
    test_storage_gen_verify_cert_req();

}
