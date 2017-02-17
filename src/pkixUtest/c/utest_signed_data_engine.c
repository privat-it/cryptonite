/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "cryptonite_manager.h"
#include "asn1_utils.h"
#include "signed_data.h"
#include "signed_data_engine.h"
#include "signer_info_engine.h"
#include "cert.h"
#include "crl.h"

static SignAdapter *create_sa(const char *path_priv_key, const char *path_cert)
{
    SignAdapter *sa = NULL;
    ByteArray *cert_ba = NULL;
    ByteArray *private_key = NULL;
    Certificate_t *certificate = cert_alloc();

    ASSERT_RET_OK(ba_alloc_from_file(path_priv_key, &private_key));
    ASSERT_RET_OK(ba_alloc_from_file(path_cert, &cert_ba));
    ASSERT_RET_OK(cert_decode(certificate, cert_ba));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, certificate, &sa));

cleanup:

    BA_FREE(private_key, cert_ba);
    cert_free(certificate);

    return sa;
}

static DigestAdapter *create_da(const char *path_cert)
{
    DigestAdapter *da = NULL;
    Certificate_t *certificate = cert_alloc();
    ByteArray *cert_ba = NULL;

    ASSERT_RET_OK(ba_alloc_from_file(path_cert, &cert_ba));
    ASSERT_RET_OK(cert_decode(certificate, cert_ba));

    ASSERT_RET_OK(digest_adapter_init_by_cert(certificate, &da));

cleanup:

    ba_free(cert_ba);
    cert_free(certificate);

    return da;
}

static void test_esigner_info_alloc(SignAdapter *sa, DigestAdapter *da, SignerInfoEngine **signer)
{
    SignerInfoEngine *signer_info_ctx = NULL;

    ASSERT_RET_OK(esigner_info_alloc(sa, da, NULL, &signer_info_ctx));
    *signer = signer_info_ctx;
    signer_info_ctx = NULL;

cleanup:

    esigner_info_free(signer_info_ctx);
}

static void test_esigned_data_generate(void)
{
    DigestAdapter *da1 = NULL;
    DigestAdapter *da2 = NULL;
    SignAdapter *sa1 = NULL;
    SignAdapter *sa2 = NULL;
    VerifyAdapter *va1 = NULL;
    VerifyAdapter *va2 = NULL;

    Certificate_t *cert1 = cert_alloc();
    Certificate_t *cert2 = cert_alloc();
    CertificateList_t *crl = crl_alloc();
    RevocationInfoChoice_t *revoc_info_choice = NULL;

    SignedDataEngine *signed_data_engine = NULL;
    SignerInfoEngine *signer_info_engine = NULL;
    SignerInfoEngine *signer = NULL;
    SignedData_t *sdata = sdata_alloc();
    EncapsulatedContentInfo_t *content = NULL;
    Attribute_t *signed_attribute = NULL;

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;
    ByteArray *signed_attr = ba_alloc_from_le_hex_string("301C06092A864886F70D010905310F170D3136303232363039323231325A");

    const char *path_priv_key1 = "src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_private_key_ba.dat";
    const char *path_cert1 = "src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer";
    const char *path_priv_key2 = "src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_private_key_ba.dat";
    const char *path_cert2 = "src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_certificate.cer";

    bool has_certs, has_crls;
    time_t signing_time, exp_signing_time;
    struct tm timeinfo;

    sa1 = create_sa(path_priv_key1, path_cert1);
    da1 = create_da(path_cert1);
    test_esigner_info_alloc(sa1, da1, &signer_info_engine);

    ASSERT_NOT_NULL(signed_attribute = asn_decode_ba_with_alloc(&Attribute_desc, signed_attr));
    ASSERT_RET_OK(esigner_info_add_signed_attr(signer_info_engine, signed_attribute));

    ASSERT_RET_OK(esigned_data_alloc(signer_info_engine, &signed_data_engine));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/signed_data.dat", &buffer));
    ASSERT_RET_OK(sdata_decode(sdata, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(sdata_get_content(sdata, &content));
    ASSERT_RET_OK(esigned_data_set_content_info(signed_data_engine, content));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/crl.dat", &buffer));
    ASSERT_RET_OK(crl_decode(crl, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(esigned_data_add_crl(signed_data_engine, crl));

    ASSERT_RET_OK(ba_alloc_from_file(path_cert1, &buffer));
    ASSERT_RET_OK(cert_decode(cert1, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file(path_cert2, &buffer));
    ASSERT_RET_OK(cert_decode(cert2, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(esigned_data_add_cert(signed_data_engine, cert1));

    sa2 = create_sa(path_priv_key2, path_cert2);
    da2 = create_da(path_cert2);
    test_esigner_info_alloc(sa2, da2, &signer);

    ASSERT_RET_OK(esigned_data_add_signer(signed_data_engine, signer));

    sdata_free(sdata);
    sdata = NULL;

    ASSERT_RET_OK(esigned_data_generate(signed_data_engine, &sdata));
    ASSERT_NOT_NULL(sdata);

    ASSERT_RET_OK(sdata_verify_signing_cert_by_adapter(sdata, da2, cert2, 0));
    ASSERT_RET_OK(sdata_verify_signing_cert_by_adapter(sdata, da1, cert1, 1));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert1, &va1));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert2, &va2));

    ASSERT_RET_OK(sdata_verify_without_data_by_adapter(sdata, da2, va2, 0));
    ASSERT_RET_OK(sdata_verify_without_data_by_adapter(sdata, da1, va1, 1));

    ASSERT_RET_OK(sdata_verify_internal_data_by_adapter(sdata, da2, va2, 0));
    ASSERT_RET_OK(sdata_verify_internal_data_by_adapter(sdata, da1, va1, 1));

    /* UTC time 2016-02-26 09:22:12. */
    // Тут получается разница в 2 часа
    timeinfo.tm_year = 116;
    timeinfo.tm_mon  = 1;
    timeinfo.tm_mday = 26;
    timeinfo.tm_hour = 11;
    timeinfo.tm_min  = 22;
    timeinfo.tm_sec  = 12;
    timeinfo.tm_isdst = -1;
    exp_signing_time = mktime(&timeinfo);

    ASSERT_RET_OK(sdata_get_signing_time(sdata, 1, &signing_time));
    ASSERT_TRUE(difftime(signing_time, exp_signing_time) == 0);

    ASSERT_RET_OK(sdata_has_certs(sdata, &has_certs));
    ASSERT_TRUE(has_certs == true);

    ASSERT_RET_OK(sdata_has_crls(sdata, &has_crls));
    ASSERT_TRUE(has_crls == true);
    ASSERT_RET_OK(sdata_get_crl_by_idx(sdata, 0, &revoc_info_choice));
    ASSERT_EQUALS_ASN(&CertificateList_desc, crl, &revoc_info_choice->choice.crl);

cleanup:

    BA_FREE(private_key, signed_attr);

    sign_adapter_free(sa1);
    sign_adapter_free(sa2);
    digest_adapter_free(da1);
    digest_adapter_free(da2);
    verify_adapter_free(va1);
    verify_adapter_free(va2);
    crl_free(crl);
    cert_free(cert1);
    cert_free(cert2);
    esigned_data_free(signed_data_engine);
    sdata_free(sdata);

    ASN_FREE(&EncapsulatedContentInfo_desc, content);
    ASN_FREE(&Attribute_desc, signed_attribute);
    ASN_FREE(&RevocationInfoChoice_desc, revoc_info_choice);
}

void utest_signed_data_engine(void)
{
    PR("%s\n", __FILE__);

    test_esigned_data_generate();
}

