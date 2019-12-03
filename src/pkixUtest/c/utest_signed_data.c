/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "pkix_errors.h"
#include "signed_data.h"
#include "asn1_utils.h"
#include "content_info.h"
#include "signer_info.h"
#include "aid.h"
#include "crl.h"
#include "cert.h"
#include "cryptonite_manager.h"

static void test_alloc_free(void)
{
    SignedData_t *sdata = sdata_alloc();
    ASSERT_NOT_NULL(sdata);

cleanup:

    sdata_free(sdata);
}

static SignedData_t *test_load(void)
{
    ByteArray *encoded = NULL;
    SignedData_t *sdata = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/signed_data.dat", &encoded));
    ASSERT_NOT_NULL(sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_decode(sdata, encoded));

cleanup:

    BA_FREE(encoded);
    return sdata;
}

static void test_encode(SignedData_t *sdata)
{
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/signed_data.dat", &decoded));

    ASSERT_RET_OK(sdata_encode(sdata, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_EQUALS_BA(decoded, encoded);
cleanup:
    BA_FREE(decoded, encoded);
}

static void test_get_version(SignedData_t *sdata)
{
    int version;

    ASSERT_RET_OK(sdata_get_version(sdata, &version));
    ASSERT_TRUE(version == 1);
cleanup:
    return;
}

static void test_set_version(SignedData_t *sdata)
{
    SignedData_t *test_sdata = NULL;

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_version(test_sdata, 1));
    ASSERT_EQUALS_ASN(&CMSVersion_desc, &test_sdata->version, &sdata->version);

cleanup:

    sdata_free(test_sdata);
}

static void test_get_digest_aid_by_idx(SignedData_t *sdata)
{
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_RET_OK(sdata_get_digest_aid_by_idx(sdata, 0, &aid));
    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, sdata->digestAlgorithms.list.array[0], aid);
cleanup:

    aid_free(aid);
}

static void test_get_digest_aid_by_idx_2(SignedData_t *sdata)
{
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_digest_aid_by_idx(sdata, sdata->digestAlgorithms.list.count + 1,
            &aid));
cleanup:

    aid_free(aid);
}

static void test_get_digest_aids(SignedData_t *sdata)
{
    DigestAlgorithmIdentifiers_t *aids = NULL;

    ASSERT_RET_OK(sdata_get_digest_aids(sdata, &aids));
    ASSERT_EQUALS_ASN(&DigestAlgorithmIdentifiers_desc, &sdata->digestAlgorithms, aids);
cleanup:

    ASN_FREE(&DigestAlgorithmIdentifiers_desc, aids);
}

static void test_set_digest_aid(SignedData_t *sdata)
{
    SignedData_t *test_sdata = NULL;

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_digest_aids(test_sdata, &sdata->digestAlgorithms));
    ASSERT_EQUALS_ASN(&DigestAlgorithmIdentifiers_desc, &test_sdata->digestAlgorithms, &sdata->digestAlgorithms);

cleanup:

    sdata_free(test_sdata);
}

static void test_get_content(SignedData_t *sdata)
{
    EncapsulatedContentInfo_t *content = NULL;

    ASSERT_RET_OK(sdata_get_content(sdata, &content));
    ASSERT_EQUALS_ASN(&EncapsulatedContentInfo_desc, content, &sdata->encapContentInfo);
cleanup:
    ASN_FREE(&EncapsulatedContentInfo_desc, content);
}

static void test_set_content(SignedData_t *sdata)
{
    SignedData_t *test_sdata = NULL;

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_content(test_sdata, &sdata->encapContentInfo));
    ASSERT_EQUALS_ASN(&CMSVersion_desc, &test_sdata->encapContentInfo, &sdata->encapContentInfo);
cleanup:
    sdata_free(test_sdata);
}

static void test_get_data(SignedData_t *sdata)
{
    ByteArray *data = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("d0a1d182d0b8d185d0b820d0b4d0bbd18f20d0bfd0bed0b4d0bfd0b8d181d0b0d0bdd0b8d18f");

    ASSERT_RET_OK(sdata_get_data(sdata, &data));
    ASSERT_EQUALS_BA(expected, data);
cleanup:
    BA_FREE(data, expected);
}

static void test_get_certs(SignedData_t *sdata)
{
    CertificateSet_t *certs = NULL;

    ASSERT_RET_OK(sdata_get_certs(sdata, &certs));
    ASSERT_EQUALS_ASN(&CertificateSet_desc, certs, sdata->certificates);

cleanup:

    ASN_FREE(&CertificateSet_desc, certs);
}

static void test_get_cert_by_idx_2(void)
{
    SignedData_t *sdata = sdata_alloc();
    CertificateChoices_t *sinfo = NULL;

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_cert_by_idx(sdata, 0, &sinfo));

cleanup:

    ASN_FREE(&CertificateChoices_desc, sinfo);
    sdata_free(sdata);

}

static void test_get_signer_info_by_idx_2(void)
{
    SignedData_t *sdata = sdata_alloc();
    SignerInfo_t *sinfo = NULL;

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_signer_info_by_idx(sdata, sdata->signerInfos.list.count, &sinfo));

cleanup:

    ASN_FREE(&SignerInfo_desc, sinfo);
    sdata_free(sdata);
}

static void test_get_crl_by_idx(void)
{
    SignedData_t *sdata = sdata_alloc();
    RevocationInfoChoice_t *rev_info = NULL;

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_crl_by_idx(sdata, 0, &rev_info));

cleanup:

    ASN_FREE(&RevocationInfoChoice_desc, rev_info);
    sdata_free(sdata);
}

static void test_set_certs(SignedData_t *sdata)
{
    SignedData_t *test_sdata = NULL;

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_certs(test_sdata, sdata->certificates));
    ASSERT_EQUALS_ASN(&CertificateSet_desc, test_sdata->certificates, sdata->certificates);

cleanup:

    sdata_free(test_sdata);
}

static void test_set_crls(void)
{
    SignedData_t *test_sdata = NULL;
    ByteArray *buffer = NULL;
    CertificateList_t *crl = crl_alloc();
    RevocationInfoChoice_t *revoc_info_choice = NULL;
    RevocationInfoChoices_t *revoc_info_choices = NULL;
    RevocationInfoChoices_t *crls = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/crl.dat", &buffer));
    ASSERT_RET_OK(crl_decode(crl, buffer));

    ASSERT_ASN_ALLOC(revoc_info_choice);
    revoc_info_choice->present = RevocationInfoChoice_PR_crl;
    ASSERT_RET_OK(asn_copy(&CertificateList_desc, crl, &revoc_info_choice->choice.crl));
    ASSERT_ASN_ALLOC(revoc_info_choices);
    ASN_SET_ADD(revoc_info_choices, revoc_info_choice);

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_crls(test_sdata, revoc_info_choices));

    ASSERT_RET_OK(sdata_get_crls(test_sdata, &crls));
    ASSERT_EQUALS_ASN(&RevocationInfoChoices_desc, revoc_info_choices, crls);

cleanup:

    ba_free(buffer);
    sdata_free(test_sdata);
    ASN_FREE(&RevocationInfoChoices_desc, revoc_info_choices);
    ASN_FREE(&RevocationInfoChoices_desc, crls);
    crl_free(crl);
}

static void test_get_crls(SignedData_t *sdata)
{
    RevocationInfoChoices_t *crls = NULL;

    ASSERT_RET_OK(sdata_get_crls(sdata, &crls));
    ASSERT_TRUE(crls == NULL);
cleanup:
    ASN_FREE(&RevocationInfoChoices_desc, crls);
}

static void test_get_signer_infos(SignedData_t *sdata)
{
    SignerInfos_t *sinfo = NULL;

    ASSERT_RET_OK(sdata_get_signer_infos(sdata, &sinfo));
    ASSERT_EQUALS_ASN(&SignerInfos_desc, sinfo, &sdata->signerInfos);
cleanup:
    ASN_FREE(&SignerInfos_desc, sinfo);
}

static void test_set_signer_infos(SignedData_t *sdata)
{
    SignedData_t *test_sdata = NULL;

    ASSERT_NOT_NULL(test_sdata = sdata_alloc());
    ASSERT_RET_OK(sdata_set_signer_infos(test_sdata, &sdata->signerInfos));
    ASSERT_EQUALS_ASN(&SignerInfos_desc, &test_sdata->signerInfos, &sdata->signerInfos);

cleanup:

    sdata_free(test_sdata);
}

static void test_get_cert_by_idx(SignedData_t *sdata)
{
    CertificateChoices_t *sinfo = NULL;

    ASSERT_RET_OK(sdata_get_cert_by_idx(sdata, 0, &sinfo));
    ASSERT_EQUALS_ASN(&CertificateChoices_desc, sinfo, sdata->certificates->list.array[0]);

cleanup:

    ASN_FREE(&CertificateChoices_desc, sinfo);
}

static void test_get_signer_info_by_idx(SignedData_t *sdata)
{
    SignerInfo_t *sinfo = NULL;

    ASSERT_RET_OK(sdata_get_signer_info_by_idx(sdata, 0, &sinfo));
    ASSERT_EQUALS_ASN(&SignerInfo_desc, sinfo, sdata->signerInfos.list.array[0]);

cleanup:

    sinfo_free(sinfo);
}

static void test_sdata_get_tst_info(SignedData_t *sdata)
{
    TSTInfo_t *info = NULL;

    ASSERT_RET(RET_PKIX_SDATA_CONTENT_NOT_TST_INFO, sdata_get_tst_info(sdata, &info));

cleanup:

    ASN_FREE(&TSTInfo_desc, info);
}

static void test_sdata_get_content_time_stamp(SignedData_t *sdata)
{
    SignedData_t *test_sdata = sdata_alloc();
    SignerInfo_t *sinfo = sinfo_alloc();
    SignerInfos_t *sinfos = NULL;
    ByteArray *buffer = NULL;
    ByteArray *exp_sid =
            ba_alloc_from_le_hex_string("308201133081FA313F303D060355040A0C36D09CD196D0BDD196D181D182D0B5D180D181D182D0B2D0BE20D18ED181D182D0B8D186D196D19720D0A3D0BAD180D0B0D197D0BDD0B83131302F060355040B0C28D090D0B4D0BCD196D0BDD196D181D182D180D0B0D182D0BED18020D086D0A2D0A120D0A6D097D09E3149304706035504030C40D0A6D0B5D0BDD182D180D0B0D0BBD18CD0BDD0B8D0B920D0B7D0B0D181D0B2D196D0B4D187D183D0B2D0B0D0BBD18CD0BDD0B8D0B920D0BED180D0B3D0B0D0BD3119301706035504050C1055412D30303031353632322D32303132310B30090603550406130255413111300F06035504070C08D09AD0B8D197D0B202143004751DEF2C78AE02000000010000004A000000");
    TspStatus status;
    time_t content_time_stamp, exp_content_time_stamp;
    SignerIdentifier_t *signer_identifier = NULL;
    EncapsulatedContentInfo_t *content = NULL;
    DigestAlgorithmIdentifiers_t *aids = NULL;
    struct tm *timeinfo = NULL;

    //Тут разница в два часа
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 116;
    timeinfo->tm_mon  = 1;
    timeinfo->tm_mday = 26;
    timeinfo->tm_hour = 11;
    timeinfo->tm_min  = 22;
    timeinfo->tm_sec  = 12;
    timeinfo->tm_isdst = -1;
    exp_content_time_stamp = mktime(timeinfo);
    free(timeinfo);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/cms_sign/SignInfo_1.dat", &buffer));
    ASSERT_RET_OK(sinfo_decode(sinfo, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_ASN_ALLOC(sinfos);
    ASN_SET_ADD(sinfos, sinfo);

    ASSERT_RET_OK(sdata_get_content(sdata, &content));
    ASSERT_RET_OK(sdata_get_digest_aids(sdata, &aids));

    ASSERT_RET_OK(sdata_init(test_sdata, 1, aids, content, sinfos));

    ASSERT_RET_OK(sdata_get_content_time_stamp(test_sdata, 0, &status, &content_time_stamp, &signer_identifier));
    ASSERT_TRUE(status == TSP_INVALID_DATA);
    ASSERT_TRUE(difftime(exp_content_time_stamp, content_time_stamp) == 0);
    ASSERT_TRUE(signer_identifier != NULL);
    ASSERT_RET_OK(asn_encode_ba(&SignerIdentifier_desc, signer_identifier, &buffer));
    ASSERT_EQUALS_BA(exp_sid, buffer);
    ba_free(buffer);
    buffer = NULL;

cleanup:

    ba_free(exp_sid);
    sdata_free(test_sdata);
    ASN_FREE(&SignerInfos_desc, sinfos);
    ASN_FREE(&EncapsulatedContentInfo_desc, content);
    ASN_FREE(&DigestAlgorithmIdentifiers_desc, aids);
    ASN_FREE(&SignerIdentifier_desc, signer_identifier);
}

static void test_sdata_set_certs_2(void)
{
    SignedData_t *sdata = sdata_alloc();
    CertificateSet_t *certs = NULL;

    ASSERT_RET_OK(sdata_get_certs(sdata, &certs));
    ASSERT_TRUE(certs == NULL);

    ASSERT_RET_OK(sdata_set_certs(sdata, certs));
    ASSERT_TRUE(sdata->certificates == NULL);

cleanup:

    sdata_free(sdata);
    ASN_FREE(&CertificateSet_desc, certs);
}

static void test_sdata_get_signing_time(SignedData_t *sdata)
{
    time_t signing_time;
    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_signing_time(sdata, sdata->signerInfos.list.count, &signing_time));

cleanup:

    return;
}

static void test_sdata_verify(SignedData_t *sdata)
{
    DigestAdapter *da = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_verify_signing_cert_by_adapter(sdata, da, cert,
            sdata->signerInfos.list.count));
    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_verify_without_data_by_adapter(sdata, da, va,
            sdata->signerInfos.list.count));
    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_verify_internal_data_by_adapter(sdata, da, va,
            sdata->signerInfos.list.count));
    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_verify_external_data_by_adapter(sdata, da, va, buffer,
            sdata->signerInfos.list.count));

cleanup:

    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
    digest_adapter_free(da);
}

static void test_sdata_verify_signing_cert_by_adapter(void)
{
    SignedData_t *sdata = sdata_alloc();
    DigestAdapter *da = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));

    ASSERT_RET(RET_PKIX_SDATA_NO_SIGNERS, sdata_verify_signing_cert_by_adapter(sdata, da, cert, 0));

cleanup:

    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
    digest_adapter_free(da);
    sdata_free(sdata);
}

static void test_sdata_get_content_time_stamp_2(void)
{
    SignedData_t *sdata = sdata_alloc();
    TspStatus status;
    time_t content_time_stamp;
    SignerIdentifier_t *signer_identifier = NULL;

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sdata_get_content_time_stamp(sdata, sdata->signerInfos.list.count, &status,
            &content_time_stamp, &signer_identifier));
    ASSERT_TRUE(signer_identifier == NULL);

cleanup:

    sdata_free(sdata);
    ASN_FREE(&SignerIdentifier_desc, signer_identifier);
}

static void test_sdata_get_data(void)
{
    SignedData_t *sdata = sdata_alloc();
    ByteArray *data = NULL;

    ASSERT_RET(RET_PKIX_SDATA_CONTENT_NOT_DATA, sdata_get_data(sdata, &data));
    ASSERT_TRUE(data == NULL);

cleanup:

    ba_free(data);
    sdata_free(sdata);
}

static void test_get_digest_aids_2(void)
{
    DigestAlgorithmIdentifiers_t *aids = NULL;

    ASSERT_RET(RET_INVALID_PARAM, sdata_get_digest_aids(NULL, &aids));
    ASSERT_TRUE(aids == NULL);

cleanup:

    ASN_FREE(&DigestAlgorithmIdentifiers_desc, aids);
}

static void test_get_content_2(void)
{
    EncapsulatedContentInfo_t *content = NULL;

    ASSERT_RET(RET_INVALID_PARAM, sdata_get_content(NULL, &content));
    ASSERT_TRUE(content == NULL);

cleanup:

    ASN_FREE(&EncapsulatedContentInfo_desc, content);
}

static void test_get_certs_2(void)
{
    CertificateSet_t *certs = NULL;

    ASSERT_RET(RET_INVALID_PARAM, sdata_get_certs(NULL, &certs));
    ASSERT_TRUE(certs == NULL);

cleanup:

    ASN_FREE(&CertificateSet_desc, certs);
}

static void test_set_certs_3(SignedData_t *sdata)
{
    ASSERT_RET(RET_INVALID_PARAM, sdata_set_certs(NULL, sdata->certificates));

cleanup:

    return;
}

static void test_set_crls_2(void)
{
    SignedData_t *test_sdata = sdata_alloc();
    ByteArray *buffer = NULL;
    CertificateList_t *crl = crl_alloc();
    RevocationInfoChoice_t *revoc_info_choice = NULL;
    RevocationInfoChoices_t *revoc_info_choices = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/crl.dat", &buffer));
    ASSERT_RET_OK(crl_decode(crl, buffer));

    ASSERT_ASN_ALLOC(revoc_info_choice);
    revoc_info_choice->present = RevocationInfoChoice_PR_crl;
    ASSERT_RET_OK(asn_copy(&CertificateList_desc, crl, &revoc_info_choice->choice.crl));
    ASSERT_ASN_ALLOC(revoc_info_choices);
    ASN_SET_ADD(revoc_info_choices, revoc_info_choice);

    ASSERT_RET(RET_INVALID_PARAM, sdata_set_crls(NULL, revoc_info_choices));
    ASSERT_RET(RET_INVALID_PARAM, sdata_set_crls(test_sdata, NULL));

cleanup:

    ba_free(buffer);
    sdata_free(test_sdata);
    ASN_FREE(&RevocationInfoChoices_desc, revoc_info_choices);
    crl_free(crl);
}

static void test_sdata_init(SignedData_t *sdata)
{
    ASSERT_RET(RET_INVALID_PARAM, sdata_init(NULL, 0, &sdata->digestAlgorithms, &sdata->encapContentInfo, &sdata->signerInfos));
    ASSERT_RET(RET_INVALID_PARAM, sdata_init(sdata, 0, NULL, &sdata->encapContentInfo, &sdata->signerInfos));
    ASSERT_RET(RET_INVALID_PARAM, sdata_init(sdata, 0, &sdata->digestAlgorithms, NULL, &sdata->signerInfos));
    ASSERT_RET(RET_INVALID_PARAM, sdata_init(sdata, 0, &sdata->digestAlgorithms, &sdata->encapContentInfo, NULL));

cleanup:

    return;
}

void utest_signed_data(void)
{
    PR("%s\n", __FILE__);

    SignedData_t *sdata = NULL;

    test_alloc_free();

    sdata = test_load();
    ASSERT_NOT_NULL(sdata);

    test_encode(sdata);
    test_get_version(sdata);
    test_set_version(sdata);
    test_get_digest_aid_by_idx(sdata);
    test_get_digest_aid_by_idx_2(sdata);
    test_get_digest_aids(sdata);
    test_set_digest_aid(sdata);
    test_get_content(sdata);
    test_set_content(sdata);
    test_get_data(sdata);
    test_get_certs(sdata);
    test_get_cert_by_idx_2();
    test_get_signer_info_by_idx_2();
    test_get_crl_by_idx();
    test_set_certs(sdata);
    test_set_crls();
    test_get_crls(sdata);
    test_get_signer_infos(sdata);
    test_set_signer_infos(sdata);
    test_get_cert_by_idx(sdata);
    test_get_signer_info_by_idx(sdata);
    test_sdata_get_tst_info(sdata);
    test_sdata_get_content_time_stamp(sdata);
    test_sdata_set_certs_2();
    test_sdata_get_signing_time(sdata);
    test_sdata_verify(sdata);
    test_sdata_verify_signing_cert_by_adapter();
    test_sdata_get_content_time_stamp_2();
    test_sdata_get_data();
    test_get_digest_aids_2();
    test_get_content_2();
    test_get_certs_2();
    test_set_certs_3(sdata);
    test_set_crls_2();
    test_sdata_init(sdata);

cleanup:

    sdata_free(sdata);
}
