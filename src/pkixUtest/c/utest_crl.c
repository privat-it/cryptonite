/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "asn1_utils.h"
#include "cert.h"
#include "crl.h"
#include "aid.h"
#include "pkix_errors.h"
#include "exts.h"
#include "ext.h"
#include "cryptonite_manager.h"

static CertificateList_t *load_test_data(void)
{
    ByteArray *decoded = NULL;
    CertificateList_t *crl = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/crl.dat", &decoded));
    ASSERT_NOT_NULL(decoded);
    ASSERT_NOT_NULL(crl = crl_alloc());

    ASSERT_RET_OK(crl_decode(crl, decoded));

cleanup:
    BA_FREE(decoded);
    return crl;
}

static void test_encode(const CertificateList_t *crl)
{
    ByteArray *decoded = NULL;
    ByteArray *actual = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/crl.dat", &decoded));
    ASSERT_RET_OK(crl_encode(crl, &actual));
    ASSERT_EQUALS_BA(decoded, actual);

cleanup:
    BA_FREE(decoded, actual);
}

static void test_crl_get_tbs(const CertificateList_t *crl)
{
    TBSCertList_t *tbs_crl = NULL;
    ByteArray *tbs_crl_ba = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "308201FC020101300D06092A864886F70D0101050500305F31233021060355040A131A53616D706C65205369676E6572204F7267616"
            "E697A6174696F6E311B3019060355040B131253616D706C65205369676E657220556E6974311B30190603550403131253616D706C65"
            "205369676E65722043657274170D3133303231383130333230305A170D3133303231383130343230305A30820136303C02031479471"
            "70D3133303231383130323231325A3026300A0603551D1504030A010330180603551D180411180F3230313330323138313032323030"
            "5A303C0203147948170D3133303231383130323232325A3026300A0603551D1504030A010630180603551D180411180F32303133303"
            "231383130323230305A303C0203147949170D3133303231383130323233325A3026300A0603551D1504030A010430180603551D1804"
            "11180F32303133303231383130323230305A303C020314794A170D3133303231383130323234325A3026300A0603551D1504030A010"
            "130180603551D180411180F32303133303231383130323230305A303C020314794B170D3133303231383130323235315A3026300A06"
            "03551D1504030A010530180603551D180411180F32303133303231383130323230305AA02F302D301F0603551D23041830168014BE1"
            "201CCAAEA1180DA2EADB2EAC7B5FB9FF9AD34300A0603551D140403020103");

    ASSERT_NOT_NULL(expected);
    ASSERT_RET_OK(crl_get_tbs(crl, &tbs_crl));
    ASSERT_RET_OK(asn_encode_ba(&TBSCertList_desc, tbs_crl, &tbs_crl_ba));

    ASSERT_EQUALS_BA(expected, tbs_crl_ba);
cleanup:
    BA_FREE(expected, tbs_crl_ba);
    ASN_FREE(&TBSCertList_desc, tbs_crl);
}

static void test_crl_set_tbs(const CertificateList_t *crl)
{
    CertificateList_t *crl_temp = NULL;

    ASSERT_NOT_NULL(crl_temp = crl_alloc());
    ASSERT_RET_OK(crl_set_tbs(crl_temp, &crl->tbsCertList));

    ASSERT_EQUALS_ASN(&TBSCertList_desc, &crl->tbsCertList, &crl_temp->tbsCertList);

cleanup:
    crl_free(crl_temp);
}

static void test_crl_get_sign_aid(const CertificateList_t *crl)
{
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *aid_ba = NULL;
    ByteArray *exp_aid_ba = ba_alloc_from_le_hex_string("300D06092A864886F70D0101050500");

    ASSERT_NOT_NULL(exp_aid_ba);
    ASSERT_RET_OK(crl_get_sign_aid(crl, &aid));
    ASSERT_RET_OK(aid_encode(aid, &aid_ba));

    ASSERT_EQUALS_BA(exp_aid_ba, aid_ba);
cleanup:
    BA_FREE(exp_aid_ba, aid_ba);
    aid_free(aid);
}

static void test_crl_set_sign_aid(const CertificateList_t *crl)
{
    CertificateList_t *crl_temp = NULL;

    ASSERT_NOT_NULL(crl_temp = crl_alloc());
    ASSERT_RET_OK(crl_set_sign_aid(crl_temp, &crl->signatureAlgorithm));

    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, &crl->signatureAlgorithm, &crl_temp->signatureAlgorithm);
cleanup:
    crl_free(crl_temp);
}

static void test_crl_init_by_sign(const CertificateList_t *crl)
{
    CertificateList_t *crl_temp = NULL;

    ASSERT_NOT_NULL(crl_temp = crl_alloc());
    ASSERT_RET_OK(crl_init_by_sign(crl_temp, &crl->tbsCertList, &crl->signatureAlgorithm, &crl->signatureValue));

    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, &crl->signatureAlgorithm, &crl_temp->signatureAlgorithm);
    ASSERT_EQUALS_ASN(&TBSCertList_desc, &crl->tbsCertList, &crl_temp->tbsCertList);
    ASSERT_EQUALS_ASN(&BIT_STRING_desc, &crl->signatureValue, &crl_temp->signatureValue);

cleanup:

    crl_free(crl_temp);
}

static void test_crl_init_by_adapter(const CertificateList_t *crl)
{
    CertificateList_t *crl_temp = NULL;
    SignAdapter *sa = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;
    AlgorithmIdentifier_t *exp_aid = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(sa->get_sign_alg(sa, &exp_aid));

    ASSERT_NOT_NULL(crl_temp = crl_alloc());
    ASSERT_RET_OK(crl_init_by_adapter(crl_temp, &crl->tbsCertList, sa));

    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, exp_aid, &crl_temp->signatureAlgorithm);
    ASSERT_EQUALS_ASN(&TBSCertList_desc, &crl->tbsCertList, &crl_temp->tbsCertList);

cleanup:

    BA_FREE(private_key, buffer);
    sign_adapter_free(sa);
    cert_free(cert);
    crl_free(crl_temp);
    aid_free(exp_aid);
}

static void test_crl_get_sign(const CertificateList_t *crl)
{
    BIT_STRING_t *sign = NULL;
    ByteArray *sign_ba = NULL;
    ByteArray *exp_ba = ba_alloc_from_le_hex_string(
            "03820101004221BE81F1C37976665BCE21138A68A8B43CBE16C3AF4BDDCB78359290D8D74C6FFE6C6827AE6DDA429801EE1793F0BDA"
            "8EECD90B635F60DA4CE4982F79D9FC86E7FD1F12D20F846CD431764E7F95AE82111C62469F84D93506F0B0DBD786153214462AF0A0B"
            "92232506D0CC065BAC1AA95B5DE8AEF5BBBBE1214FD389D7FA65276C4CC8693CF16E3D489DE23DBD537AB5D1218517A702B750F38EF"
            "51C0B01C6847034D8C7A7EF41206450033CB5A62E0D0782529487589959C046B5EBFFF15B148A3CA3B0CD3BD82E94B794F0372AEBB6"
            "16FDE76F9E2A59B12CD813D28E61558C635E1B702D0B0BED0661AF2A403350CB62A4239220C8EE196FB7B42E0C64C9");

    ASSERT_NOT_NULL(exp_ba);
    ASSERT_RET_OK(crl_get_sign(crl, &sign));
    ASSERT_RET_OK(asn_encode_ba(&BIT_STRING_desc, sign, &sign_ba));

    ASSERT_EQUALS_BA(exp_ba, sign_ba);
cleanup:
    ASN_FREE(&BIT_STRING_desc, sign);
    BA_FREE(exp_ba, sign_ba);
}

static void test_crl_set_sign(const CertificateList_t *crl)
{
    CertificateList_t *crl_temp = NULL;

    ASSERT_NOT_NULL(crl_temp = crl_alloc());
    ASSERT_RET_OK(crl_set_sign(crl_temp, &crl->signatureValue));

    ASSERT_EQUALS_ASN(&BIT_STRING_desc, &crl->signatureValue, &crl_temp->signatureValue);
cleanup:
    crl_free(crl_temp);
}

static void test_crl_check_cert(const CertificateList_t *crl)
{
    Certificate_t *cert = NULL;
    ByteArray *decoded = NULL;
    bool answ;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));
    ASSERT_NOT_NULL(decoded);
    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(crl_check_cert(crl, cert, &answ));

    ASSERT_TRUE(answ == false);
cleanup:

    ba_free(decoded);
    cert_free(cert);

}

static void test_crl_get_cert_info(const CertificateList_t *crl)
{
    Certificate_t *cert = NULL;
    ByteArray *decoded = NULL;
    RevokedCertificate_t *rc = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));
    ASSERT_NOT_NULL(decoded);
    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    //rc == NULL так как сертификат не отозванный
    ASSERT_RET(RET_PKIX_OBJ_NOT_FOUND, crl_get_cert_info(crl, cert, &rc));
    ASSERT_TRUE(rc == NULL);

cleanup:
    ba_free(decoded);
    cert_free(cert);
}

static void test_crl_get_cert_info_by_sn(const CertificateList_t *crl)
{
    Certificate_t *cert = NULL;
    ByteArray *decoded = NULL;
    ByteArray *sn = NULL;
    RevokedCertificate_t *rc = NULL;
    INTEGER_t *serial_number = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));
    ASSERT_NOT_NULL(decoded);
    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));
    ASSERT_RET_OK(cert_get_sn(cert, &sn));

    ASSERT_RET_OK(asn_create_integer_from_ba(sn, &serial_number));

    //rc == NULL так как сертификат не отозванный
    ASSERT_RET(RET_PKIX_OBJ_NOT_FOUND, crl_get_cert_info_by_sn(crl, serial_number, &rc));
    ASSERT_TRUE(rc == NULL);

cleanup:

    BA_FREE(decoded, sn);
    cert_free(cert);
    ASN_FREE(&INTEGER_desc, serial_number);
    ASN_FREE(&RevokedCertificate_desc, rc);
}

static void test_crl_is_full(const CertificateList_t *crl)
{
    bool answ;

    ASSERT_RET_OK(crl_is_full(crl, &answ));
    ASSERT_TRUE(answ == false);

cleanup:
    return;
}

static void test_crl_is_delta(const CertificateList_t *crl)
{
    bool answ;

    ASSERT_RET_OK(crl_is_delta(crl, &answ));
    ASSERT_TRUE(answ == false);

cleanup:
    return;
}

static void test_crl(void)
{
    ByteArray *crl_number_exp = ba_alloc_from_be_hex_string("4461");
    CertificateList_t *crl = crl_alloc();
    ByteArray *buffer = NULL;
    ByteArray *crl_number = NULL;
    time_t act_this_update;
    time_t exp_this_update = 1473454396;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/CZO-Full.crl", &buffer));
    ASSERT_RET_OK(crl_decode(crl, buffer));

    ASSERT_RET_OK(crl_get_crl_number(crl, &crl_number));
    ASSERT_EQUALS_BA(crl_number_exp, crl_number);

    ASSERT_RET_OK(crl_get_this_update(crl, &act_this_update));
    ASSERT_TRUE(exp_this_update == act_this_update);

cleanup:

    BA_FREE(buffer, crl_number, crl_number_exp);
    crl_free(crl);
}

static void test_crl_get_distribution_points(const CertificateList_t *crl)
{
    char **url = NULL;
    size_t url_len = 0;
    Extension_t *ext = NULL;
    ByteArray *ext_ba =
            ba_alloc_from_le_hex_string("303D0603551D1F043630343032A030A02E862C687474703A2F2F637A6F2E676F762E75612F646F776E6C6F61642F63726C732F435A4F2D46756C6C2E63726C");
    size_t i;
    char *exp_url = "http://czo.gov.ua/download/crls/CZO-Full.crl";

    ASSERT_NOT_NULL(ext = asn_decode_ba_with_alloc(&Extension_desc, ext_ba));
    ASSERT_RET_OK(exts_add_extension(crl->tbsCertList.crlExtensions, ext));
    ASSERT_RET_OK(crl_get_distribution_points(crl, &url, &url_len));
    ASSERT_TRUE(url_len == 1);
    ASSERT_TRUE(strcmp(url[0], exp_url) == 0);

cleanup:

    ba_free(ext_ba);
    ext_free(ext);

    for (i = 0; i < url_len; i++) {
        free(url[i]);
    }
    free(url);
}

static void test_crl_check_cert_2(void)
{
    CertificateList_t *crl = crl_alloc();
    Certificate_t *cert = cert_alloc();
    bool answ;

    ASSERT_RET_OK(crl_check_cert(crl, cert, &answ));
    ASSERT_TRUE(answ == false);

cleanup:

    cert_free(cert);
    crl_free(crl);
}

static void test_crl_get_cert_info_by_sn_2(void)
{
    CertificateList_t *crl = crl_alloc();
    Certificate_t *cert = cert_alloc();
    ByteArray *decoded = NULL;
    ByteArray *sn = NULL;
    RevokedCertificate_t *rc = NULL;
    INTEGER_t *serial_number = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));
    ASSERT_RET_OK(cert_decode(cert, decoded));
    ASSERT_RET_OK(cert_get_sn(cert, &sn));

    ASSERT_RET_OK(asn_create_integer_from_ba(sn, &serial_number));

    ASSERT_RET(RET_PKIX_OBJ_NOT_FOUND, crl_get_cert_info_by_sn(crl, serial_number, &rc));
    ASSERT_TRUE(rc == NULL);

cleanup:

    BA_FREE(decoded, sn);
    cert_free(cert);
    crl_free(crl);
    ASN_FREE(&INTEGER_desc, serial_number);
    ASN_FREE(&RevokedCertificate_desc, rc);
}

static void test_crl_is_full_2(void)
{
    CertificateList_t *crl = crl_alloc();
    bool answ;

    ASSERT_RET_OK(crl_is_full(crl, &answ));
    ASSERT_TRUE(answ == false);

cleanup:

    crl_free(crl);
}

static void test_crl_is_delta_2(void)
{
    CertificateList_t *crl = crl_alloc();
    bool answ;

    ASSERT_RET_OK(crl_is_delta(crl, &answ));
    ASSERT_TRUE(answ == false);

cleanup:

    crl_free(crl);
}

static void test_crl_is_full_3(void)
{
    CertificateList_t *crl = crl_alloc();
    ByteArray *decoded = NULL;
    bool answ;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/CZO-Full.crl", &decoded));
    ASSERT_RET_OK(crl_decode(crl, decoded));

    ASSERT_RET_OK(crl_is_full(crl, &answ));
    ASSERT_TRUE(answ == true);

cleanup:

    ba_free(decoded);
    crl_free(crl);
}

static void test_crl_check_cert_3(void)
{
    CertificateList_t *crl = crl_alloc();
    Certificate_t *cert = cert_alloc();
    ByteArray *decoded = NULL;
    ByteArray *sn = ba_alloc_from_le_hex_string("3004751DEF2C78AE010000000100000017000000");
    bool answ;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/CZO-Full.crl", &decoded));
    ASSERT_RET_OK(crl_decode(crl, decoded));

    ASSERT_RET_OK(asn_ba2INTEGER(sn, &cert->tbsCertificate.serialNumber));

    ASSERT_RET_OK(crl_check_cert(crl, cert, &answ));
    ASSERT_TRUE(answ == true);

cleanup:

    BA_FREE(sn, decoded);
    cert_free(cert);
    crl_free(crl);
}

#if defined(__LP64__) || defined(_WIN32)

static void test_crl_get_this_update(void)
{
    CertificateList_t *crl = crl_alloc();
    PKIXTime_t *pkix_time = NULL;
    GeneralizedTime_t *generalTime = NULL;
    struct tm tm_time;
    struct tm *timeinfo = NULL;
    time_t this_update;
    time_t act_this_update;

    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 163;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    this_update = mktime(timeinfo);
    free(timeinfo);

    ASSERT_ASN_ALLOC(pkix_time);
    memcpy(&tm_time, localtime(&this_update), sizeof(tm_time));
    pkix_time->present = PKIXTime_PR_generalTime;
    generalTime = asn_time2GT(NULL, &tm_time, true);
    ASSERT_RET_OK(asn_copy(&GeneralizedTime_desc, generalTime, &pkix_time->choice.generalTime));

    ASSERT_RET_OK(asn_copy(&PKIXTime_desc, pkix_time, &crl->tbsCertList.thisUpdate));

    ASSERT_RET_OK(crl_get_this_update(crl, &act_this_update));
    ASSERT_TRUE(difftime(this_update, act_this_update) == 0);

cleanup:

    crl_free(crl);
    ASN_FREE(&PKIXTime_desc, pkix_time);
    ASN_FREE(&GeneralizedTime_desc, generalTime);
}

#endif

static void test_crl_get_tbs_2(void)
{
    TBSCertList_t *tbs_crl = NULL;

    ASSERT_RET(RET_INVALID_PARAM, crl_get_tbs(NULL, &tbs_crl));
    ASSERT_TRUE(tbs_crl == NULL);

cleanup:

    ASN_FREE(&TBSCertList_desc, tbs_crl);
}

static void test_crl_init_by_sign_2(CertificateList_t *crl)
{
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_sign(NULL, &crl->tbsCertList, &crl->signatureAlgorithm, &crl->signatureValue));
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_sign(crl, NULL, &crl->signatureAlgorithm, &crl->signatureValue));
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_sign(crl, &crl->tbsCertList, NULL, &crl->signatureValue));
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_sign(crl, &crl->tbsCertList, &crl->signatureAlgorithm, NULL));

cleanup:

    return;
}

static void test_crl_init_by_adapter_2(CertificateList_t *crl)
{
    Certificate_t *cert_tmp = cert_alloc();
    SignAdapter *sa = NULL;
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert_tmp, buffer));
    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert_tmp, &sa));

    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_adapter(NULL, &crl->tbsCertList, sa));
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_adapter(crl, NULL, sa));
    ASSERT_RET(RET_INVALID_PARAM, crl_init_by_adapter(crl, &crl->tbsCertList, NULL));

cleanup:

    sign_adapter_free(sa);
    BA_FREE(private_key, buffer);
    cert_free(cert_tmp);
}
void utest_crl(void)
{
    CertificateList_t *crl = NULL;

    PR("%s\n", __FILE__);

    crl = load_test_data();

    if (crl) {
        test_encode(crl);
        test_crl_get_tbs(crl);
        test_crl_set_tbs(crl);
        test_crl_get_sign_aid(crl);
        test_crl_set_sign_aid(crl);
        test_crl_init_by_sign(crl);
        test_crl_init_by_adapter(crl);
        test_crl_get_sign(crl);
        test_crl_set_sign(crl);
        test_crl_check_cert(crl);
        test_crl_get_cert_info(crl);
        test_crl_get_cert_info_by_sn(crl);
        test_crl_is_delta(crl);
        test_crl_is_full(crl);
        test_crl();
        test_crl_get_distribution_points(crl);
        test_crl_check_cert_2();
        test_crl_get_cert_info_by_sn_2();
        test_crl_is_full_2();
        test_crl_is_delta_2();
        test_crl_is_full_3();
        test_crl_check_cert_3();

#if defined(__LP64__) || defined(_WIN32)
        test_crl_get_this_update();
#endif

        test_crl_get_tbs_2();
        test_crl_init_by_sign_2(crl);
        test_crl_init_by_adapter_2(crl);
    }

    crl_free(crl);
}
