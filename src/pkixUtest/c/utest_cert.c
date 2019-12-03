/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "cert.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "oids.h"
#include "aid.h"
#include "spki.h"
#include "ext.h"
#include "exts.h"
#include "pkix_errors.h"
#include "cryptonite_manager.h"

static Certificate_t *load_test_data(void)
{
    ByteArray *decoded = NULL;
    Certificate_t *cert = NULL;;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(cert_check_validity(cert));

cleanup:

    BA_FREE(decoded);

    return cert;
}

static void utest_cert_encode(Certificate_t *cert)
{
    ByteArray *expected = NULL;
    ByteArray *actual = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &expected));
    ASSERT_RET_OK(cert_encode(cert, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
}

static void utest_get_version(Certificate_t *cert)
{
    long version;

    ASSERT_RET_OK(cert_get_version(cert, &version));
    ASSERT_TRUE(version == 2);

cleanup:
    return;
}

static void utest_get_sn(Certificate_t *cert)
{
    ByteArray *actual_sn = NULL;
    ByteArray *expected_sn = ba_alloc_from_be_hex_string("33B6CB7BF721B9CE02000000020000003DB93A00");

    ASSERT_NOT_NULL(expected_sn);
    ASSERT_RET_OK(cert_get_sn(cert, &actual_sn));
    ASSERT_NOT_NULL(actual_sn);

    ASSERT_EQUALS_BA(expected_sn, actual_sn);
cleanup:
    BA_FREE(expected_sn, actual_sn);
}

static void utest_get_not_before(Certificate_t *cert)
{
    time_t actual;
    time_t expected = 1424965980;

    ASSERT_RET_OK(cert_get_not_before(cert, &actual));
    ASSERT_TRUE(expected == actual);
cleanup:
    return;
}

static void utest_get_not_after(Certificate_t *cert)
{
    time_t actual;
    time_t expected = 1582732380;

    ASSERT_RET_OK(cert_get_not_after(cert, &actual));
    ASSERT_TRUE(expected == actual);
cleanup:
    return;
}

static void utest_get_tbs_info(Certificate_t *cert)
{
    ByteArray *tbs_info_actual = NULL;
    ByteArray *tbs_actual = NULL;
    ByteArray *tbs_info_expected = NULL;
    ByteArray *tbs_info = NULL;
    TBSCertificate_t *tbs_cert = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &tbs_info));
    ASSERT_NOT_NULL(tbs_info);
    //Обрезаем байты, указывающие длину
    ASSERT_NOT_NULL(tbs_info_expected = ba_copy_with_alloc(tbs_info, 4, 0));

    //Обрезаем байты, которые не относятся к сертификату
    ASSERT_RET_OK(ba_change_len(tbs_info_expected, 1898));

    ASSERT_RET_OK(cert_get_tbs_info(cert, &tbs_info_actual));
    ASSERT_NOT_NULL(tbs_info_actual);
    ASSERT_EQUALS_BA(tbs_info_expected, tbs_info_actual);

    ASSERT_RET_OK(cert_get_tbs_cert(cert, &tbs_cert));
    ASSERT_RET_OK(asn_encode_ba(&TBSCertificate_desc, tbs_cert, &tbs_actual));
    ASSERT_EQUALS_BA(tbs_info_expected, tbs_actual);

cleanup:

    BA_FREE(tbs_info_expected, tbs_info_actual, tbs_info, tbs_actual);
    ASN_FREE(&TBSCertificate_desc, tbs_cert);

}

static void utest_get_aid(Certificate_t *cert)
{
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("300D060B2A86240201010101030101");

    ASSERT_RET_OK(cert_get_aid(cert, &aid));
    ASSERT_NOT_NULL(aid);
    ASSERT_RET_OK(aid_encode(aid, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    aid_free(aid);
    BA_FREE(actual, expected);
}

static void utest_get_sign(Certificate_t *cert)
{
    BIT_STRING_t *sign = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("03430004406826CBBDA6FC646B0AA907A542B3389A76B8354219C0EC987BEEDC012D8C3"
                    "82B16ACF9742878FBF4252ABFB16D63D479C630CB2808B58B95CE2AE9079F061C16");

    ASSERT_RET_OK(cert_get_sign(cert, &sign));
    ASSERT_NOT_NULL(sign);
    ASSERT_RET_OK(asn_encode_ba(&BIT_STRING_desc, sign, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    ASN_FREE(&BIT_STRING_desc, sign);
    BA_FREE(actual, expected);
}

static void utest_get_key_usage(Certificate_t *cert)
{
    BIT_STRING_t *key = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("03020308");

    ASSERT_RET_OK(cert_get_key_usage(cert, &key));
    ASSERT_NOT_NULL(key);
    ASSERT_RET_OK(asn_encode_ba(&BIT_STRING_desc, key, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:
    ASN_FREE(&BIT_STRING_desc, key);
    BA_FREE(actual, expected);
}

static void utest_get_basic_constrains(Certificate_t *cert)
{
    int cnt;

    ASSERT_RET_OK(cert_get_basic_constrains(cert, &cnt));
    ASSERT_TRUE(cnt == -1);

cleanup:
    return;
}

static void utest_is_ocsp_cert(Certificate_t *cert)
{
    bool is_ocsp_cert;

    ASSERT_RET_OK(cert_is_ocsp_cert(cert, &is_ocsp_cert));
    ASSERT_TRUE(is_ocsp_cert == false);

cleanup:
    return;
}

static void utest_get_spki(Certificate_t *cert)
{
    SubjectPublicKeyInfo_t *spki = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "3082015130820112060B2A86240201010101030101308201013081BC300F020201AF30090201010201030201050201010436"
            "F3CA40C669A4DA173149CA12C32DAE186B53AC6BC6365997DEAEAE8AD2D888F9BFD53401694EF9C4273D8CFE6DC28F706A0F"
            "4910CE0302363FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCB"
            "AF80D90C7A95110504CF04367C857C94C5433BFD991E17C22684065850A9A249ED7BC249AE5A4E878689F872EF7AD524082E"
            "C3038E9AEDE7BA6BA13381D979BA621A0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17"
            "F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040339000436BA9F4952D8E040AF1BE2116994"
            "10B9160036AB6F14770A359B57EE98EDB06C49A35024D36D6C0FEB55416C449E8D9276268FBD4A7127");

    ASSERT_RET_OK(cert_get_spki(cert, &spki));
    ASSERT_RET_OK(spki_encode(spki, &actual));
    ASSERT_NOT_NULL(actual);
    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
    spki_free(spki);
}

static void utest_get_subj_key_id(Certificate_t *cert)
{
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("1042179BB3EC751BD51158AB0FAB18B29B1DF55A872F8622E629C4A595BA3665");

    ASSERT_RET_OK(cert_get_subj_key_id(cert, &actual));
    ASSERT_NOT_NULL(actual);
    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
}

static void utest_get_auth_key_id(Certificate_t *cert)
{
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("33B6CB7BF721B9CEEEE3DE2E62FEEA3B701A4B6760BC1C2FCF356516B50EBCAA");

    ASSERT_RET_OK(cert_get_auth_key_id(cert, &actual));
    ASSERT_NOT_NULL(actual);
    ASSERT_EQUALS_BA(expected, actual);
cleanup:
    BA_FREE(expected, actual);
}

static void utest_get_ext_value(Certificate_t *cert)
{
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string("3031302f06082b060105050730038623687474703a2f2f6163736"
            "b6964642e676f762e75612f73657276696365732f7473702f");

    ASSERT_RET_OK(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_SUBJECT_INFO_ACCESS_EXTENSION_ID), &actual));

    ASSERT_NOT_NULL(actual);
    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
}

static void utest_get_tsp_url(Certificate_t *cert)
{
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_str("http://acskidd.gov.ua/services/tsp/");

    ASSERT_RET_OK(cert_get_tsp_url(cert, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    BA_FREE(expected, actual);
}

static void utest_cert_init_by_sign(Certificate_t *cert)
{
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_init_by_sign(cert_tmp, &cert->tbsCertificate, &cert->signatureAlgorithm, &cert->signature));

    ASSERT_EQUALS_ASN(&TBSCertificate_desc, &cert->tbsCertificate, &cert_tmp->tbsCertificate);
    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, &cert->signatureAlgorithm, &cert_tmp->signatureAlgorithm);
    ASSERT_EQUALS_ASN(&BIT_STRING_desc, &cert->signature, &cert_tmp->signature);

cleanup:

    cert_free(cert_tmp);
}

static void utest_cert_get_critical_ext_oids(Certificate_t *cert)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;
    size_t i;

    ASSERT_RET_OK(cert_get_critical_ext_oids(cert, &oids, &cnt));
    ASSERT_TRUE(cnt == 5);

    ASSERT_EQUALS_OID(OID_KEY_USAGE_EXTENSION_ID, oids[0]);
    ASSERT_EQUALS_OID(OID_EXT_KEY_USAGE_EXTENSION_ID, oids[1]);
    ASSERT_EQUALS_OID(OID_CERTIFICATE_POLICIES_EXTENSION_ID, oids[2]);
    ASSERT_EQUALS_OID(OID_BASIC_CONSTRAINTS_EXTENSION_ID, oids[3]);
    ASSERT_EQUALS_OID(OID_QC_STATEMENTS_EXTENSION_ID, oids[4]);

cleanup:

    for (i = 0; i < cnt; i++) {
        ASN_FREE(&OBJECT_IDENTIFIER_desc, oids[i]);
    }
    free(oids);
}

static void utest_cert_get_non_critical_ext_oids(Certificate_t *cert)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;
    size_t i;

    ASSERT_RET_OK(cert_get_non_critical_ext_oids(cert, &oids, &cnt));
    ASSERT_TRUE(cnt == 8);

    ASSERT_EQUALS_OID(OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID, oids[0]);
    ASSERT_EQUALS_OID(OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION_ID, oids[1]);
    ASSERT_EQUALS_OID(OID_PRIVATE_KEY_USAGE_PERIOD_EXTENSION_ID, oids[2]);
    ASSERT_EQUALS_OID(OID_SUBJECT_ALT_NAME_EXTENSION_ID, oids[3]);
    ASSERT_EQUALS_OID(OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID, oids[4]);
    ASSERT_EQUALS_OID(OID_FRESHEST_CRL_EXTENSION_ID, oids[5]);
    ASSERT_EQUALS_OID(OID_AUTHORITY_INFO_ACCESS_EXTENSION_ID, oids[6]);
    ASSERT_EQUALS_OID(OID_SUBJECT_INFO_ACCESS_EXTENSION_ID, oids[7]);

cleanup:

    for (i = 0; i < cnt; i++) {
        ASN_FREE(&OBJECT_IDENTIFIER_desc, oids[i]);
    }

    free(oids);
}

static void utest_cert_has_unsupported_critical_ext(Certificate_t *cert)
{
    bool flag;

    ASSERT_RET_OK(cert_has_unsupported_critical_ext(cert, &flag));
    ASSERT_TRUE(flag == false);

cleanup:

    return;
}

static void utest_cert_check_pubkey_and_usage(Certificate_t *cert)
{
    ByteArray *pub_key = NULL;
    ByteArray *buffer = NULL;
    bool flag;

    ASSERT_RET_OK(spki_get_pub_key(&cert->tbsCertificate.subjectPublicKeyInfo, &pub_key));

    ASSERT_RET_OK(cert_check_pubkey_and_usage(cert, pub_key, KEY_USAGE_KEY_AGREEMENT, &flag));
    ASSERT_TRUE(flag == true);

cleanup:

    BA_FREE(buffer, pub_key);
}

static void utest_cert_get_qc_statement_limit_3(Certificate_t *cert)
{
    char *currency_code = NULL;
    long amount, exponent;

    ASSERT_RET(RET_PKIX_CERT_NO_QC_STATEMENT_LIMIT, cert_get_qc_statement_limit(cert, &currency_code, &amount, &exponent));
    ASSERT_TRUE(amount == 0);
    ASSERT_TRUE(exponent == 0);
    ASSERT_TRUE(currency_code == NULL);

cleanup:

    return;
}

static void utest_cert_get_qc_statement_limit(void)
{
    ByteArray *decoded = NULL;
    Certificate_t *cert = NULL;
    char exp_currency_code[] = "EUR";
    long exp_amount = 0;
    long exp_exponent = 0;
    char *act_currency_code = NULL;
    long act_amount, act_exponent;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/rsa.cer", &decoded));

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(cert_get_qc_statement_limit(cert, &act_currency_code, &act_amount, &act_exponent));

    ASSERT_TRUE(exp_amount == act_amount);
    ASSERT_TRUE(exp_exponent == act_exponent);
    ASSERT_TRUE(strcmp(exp_currency_code, act_currency_code) == 0);

cleanup:

    free(act_currency_code);
    cert_free(cert);
    BA_FREE(decoded);
}

static void utest_cert_has_unsupported_critical_ext_2(void)
{
    bool flag;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_has_unsupported_critical_ext(cert_tmp, &flag));
    ASSERT_TRUE(flag == false);

cleanup:

    cert_free(cert_tmp);
}

static void utest_cert_get_critical_ext_oids_2(void)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_get_critical_ext_oids(cert_tmp, &oids, &cnt));
    ASSERT_TRUE(oids == NULL);
    ASSERT_TRUE(cnt == 0);

cleanup:

    cert_free(cert_tmp);
}

static void utest_cert_get_non_critical_ext_oids_2(void)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_get_non_critical_ext_oids(cert_tmp, &oids, &cnt));
    ASSERT_TRUE(oids == NULL);
    ASSERT_TRUE(cnt == 0);

cleanup:

    cert_free(cert_tmp);
}

static void utest_get_ext_value_2(void)
{
    ByteArray *value = NULL;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, cert_get_ext_value(cert_tmp,
            oids_get_oid_numbers_by_id(OID_SUBJECT_INFO_ACCESS_EXTENSION_ID), &value));
    ASSERT_TRUE(value == NULL);

cleanup:

    ba_free(value);
    cert_free(cert_tmp);
}

static void utest_get_version_2(void)
{
    long version;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_get_version(cert_tmp, &version));
    ASSERT_TRUE(version == 0);

cleanup:

    cert_free(cert_tmp);
}

static void utest_get_basic_constrains_2(void)
{
    int cnt;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_get_basic_constrains(cert_tmp, &cnt));
    ASSERT_TRUE(cnt == -1);

cleanup:

    cert_free(cert_tmp);
}

static void utest_is_ocsp_cert_2(void)
{
    bool is_ocsp_cert;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET_OK(cert_is_ocsp_cert(cert_tmp, &is_ocsp_cert));
    ASSERT_TRUE(is_ocsp_cert == false);

cleanup:

    cert_free(cert_tmp);
}

static void utest_cert_get_qc_statement_limit_2(void)
{
    char *currency_code = NULL;
    long amount, exponent;
    Certificate_t *cert_tmp = cert_alloc();

    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, cert_get_qc_statement_limit(cert_tmp, &currency_code, &amount, &exponent));
    ASSERT_TRUE(amount == 0);
    ASSERT_TRUE(exponent == 0);
    ASSERT_TRUE(currency_code == NULL);

cleanup:

    cert_free(cert_tmp);
}

static void utest_get_ext_value_3(Certificate_t *cert)
{
    ByteArray *ext = NULL;
    OidNumbers *oid_num = oids_get_oid_numbers_by_str("1.1.1");
    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, cert_get_ext_value(cert, oid_num, &ext));

cleanup:

    oids_oid_numbers_free(oid_num);
    ba_free(ext);
}

static void utest_cert_check_validity_encode(void)
{
    ByteArray *decoded = NULL;
    bool cert_check = false;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/acsk_cert.cer", &decoded));
    cert_check = cert_check_validity_encode(decoded);
    ASSERT_TRUE(cert_check == true);

cleanup:

    BA_FREE(decoded);
}

#if defined(__LP64__) || defined(_WIN32)

static void utest_cert_check_validity_with_date(void)
{
    ByteArray *decoded =
            ba_alloc_from_le_hex_string("30820402308203AAA0030201020213123456789ABCDEFF0000123456789ABCDEFF00300D060B2A862402010101010301013082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3022180F32303530303132353230303030305A180F32303533303132353230303030305A3082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040324000421D7B049230F30FD10C53CB78A347EFEE8CFBE04F0CF1660143AF44537E076834001A3023000300D060B2A86240201010101030101034300044002A251F9987A49DBFE2B5BA18217D97207D24370E40352E613E59017ACF444255C0144D80C1E92F3D7F7E1DB055663A9F24C88783A244265E10983FA1E13052C");
    Certificate_t *cert = NULL;
    time_t date;
    struct tm *timeinfo = NULL;
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 151;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    date = mktime(timeinfo);
    free(timeinfo);

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(cert_check_validity_with_date(cert, date));

cleanup:

    ba_free(decoded);
    cert_free(cert);
}

static void utest_cert_check_validity_with_date_2(void)
{
    ByteArray *decoded =
            ba_alloc_from_le_hex_string("30820402308203AAA0030201020213123456789ABCDEFF0000123456789ABCDEFF00300D060B2A862402010101010301013082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3022180F32303530303132353230303030305A180F32303533303132353230303030305A3082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040324000421D7B049230F30FD10C53CB78A347EFEE8CFBE04F0CF1660143AF44537E076834001A3023000300D060B2A86240201010101030101034300044002A251F9987A49DBFE2B5BA18217D97207D24370E40352E613E59017ACF444255C0144D80C1E92F3D7F7E1DB055663A9F24C88783A244265E10983FA1E13052C");
    Certificate_t *cert = NULL;
    time_t date;
    struct tm *timeinfo = NULL;
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 110;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    date = mktime(timeinfo);
    free(timeinfo);

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET(RET_PKIX_CERT_NOT_BEFORE_VALIDITY_ERROR, cert_check_validity_with_date(cert, date));

cleanup:

    ba_free(decoded);
    cert_free(cert);
}

static void utest_cert_check_validity_with_date_3(void)
{
    ByteArray *decoded =
            ba_alloc_from_le_hex_string("30820402308203AAA0030201020213123456789ABCDEFF0000123456789ABCDEFF00300D060B2A862402010101010301013082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3022180F32303530303132353230303030305A180F32303533303132353230303030305A3082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040324000421D7B049230F30FD10C53CB78A347EFEE8CFBE04F0CF1660143AF44537E076834001A3023000300D060B2A86240201010101030101034300044002A251F9987A49DBFE2B5BA18217D97207D24370E40352E613E59017ACF444255C0144D80C1E92F3D7F7E1DB055663A9F24C88783A244265E10983FA1E13052C");
    Certificate_t *cert = NULL;
    time_t date;
    struct tm *timeinfo = NULL;
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 154;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    date = mktime(timeinfo);
    free(timeinfo);

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET(RET_PKIX_CERT_NOT_AFTER_VALIDITY_ERROR, cert_check_validity_with_date(cert, date));

cleanup:

    ba_free(decoded);
    cert_free(cert);
}

static void utest_cert_get_not_before_2(void)
{
    ByteArray *decoded =
            ba_alloc_from_le_hex_string("30820402308203AAA0030201020213123456789ABCDEFF0000123456789ABCDEFF00300D060B2A862402010101010301013082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3022180F32303530303132353230303030305A180F32303533303132353230303030305A3082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040324000421D7B049230F30FD10C53CB78A347EFEE8CFBE04F0CF1660143AF44537E076834001A3023000300D060B2A86240201010101030101034300044002A251F9987A49DBFE2B5BA18217D97207D24370E40352E613E59017ACF444255C0144D80C1E92F3D7F7E1DB055663A9F24C88783A244265E10983FA1E13052C");
    Certificate_t *cert = NULL;
    time_t act_date;
    time_t exp_date = 2526753600;

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(cert_get_not_before(cert, &act_date));
    ASSERT_TRUE(difftime(exp_date, act_date) == 0);

cleanup:

    ba_free(decoded);
    cert_free(cert);
}

#endif

static void utest_cert_get_basic_constrains_2(void)
{
    int cnt;
    ByteArray *decoded = NULL;
    Certificate_t *cert = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test.crt", &decoded));

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, decoded));

    ASSERT_RET_OK(cert_get_basic_constrains(cert, &cnt));
    ASSERT_TRUE(cnt == 0);

cleanup:

    ba_free(decoded);
    cert_free(cert);
}

static void utest_cert_get_not_before_3(void)
{
    Certificate_t *cert = NULL;
    time_t act_date;

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET(RET_PKIX_UNSUPPORTED_PKIX_TIME, cert_get_not_before(cert, &act_date));

cleanup:

    cert_free(cert);
}

static void utest_cert_get_not_after_2(void)
{
    Certificate_t *cert = NULL;
    time_t act_date;

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET(RET_PKIX_UNSUPPORTED_PKIX_TIME, cert_get_not_after(cert, &act_date));

cleanup:

    cert_free(cert);
}

static void utest_cert_check_validity_with_date_4(void)
{
    Certificate_t *cert = NULL;
    time_t date;
    struct tm *timeinfo = NULL;
    ASSERT_NOT_NULL(timeinfo = calloc(1, sizeof(struct tm)));
    timeinfo->tm_year = 114;
    timeinfo->tm_mon  = 0;
    timeinfo->tm_mday = 25;
    timeinfo->tm_hour = 22;
    timeinfo->tm_min  = 0;
    timeinfo->tm_sec  = 0;
    timeinfo->tm_isdst = -1;
    date = mktime(timeinfo);
    free(timeinfo);

    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_check_validity_with_date(cert, date));

cleanup:

    cert_free(cert);
}

static void utest_cert_check_sid(Certificate_t *cert)
{
    SignerIdentifier_t *sid = NULL;
    SignerIdentifierIm_t *sid_im = NULL;
    ByteArray *ski = ba_alloc_from_le_hex_string("1042179BB3EC751BD51158AB0FAB18B29B1DF55A872F8622E629C4A595BA3665");
    ByteArray *sid_im_ba = NULL;

    ASSERT_ASN_ALLOC(sid_im);
    sid_im->present = SignerIdentifierIm_PR_subjectKeyIdentifier;
    ASSERT_RET_OK(asn_ba2OCTSTRING(ski, &sid_im->choice.subjectKeyIdentifier));

    ASSERT_RET_OK(asn_encode_ba(&SignerIdentifierIm_desc, sid_im, &sid_im_ba));
    ASSERT_NOT_NULL(sid = asn_decode_ba_with_alloc(&SignerIdentifier_desc, sid_im_ba));
    ASSERT_TRUE(cert_check_sid(cert, sid));

cleanup:

    BA_FREE(ski, sid_im_ba);
    ASN_FREE(&SignerIdentifierIm_desc, sid_im);
    ASN_FREE(&SignerIdentifier_desc, sid);
}

static void utest_cert_check_pubkey_and_usage_2(Certificate_t *cert)
{
    ByteArray *pub_key = NULL;
    ByteArray *buffer = NULL;
    bool flag;

    ASSERT_RET_OK(spki_get_pub_key(&cert->tbsCertificate.subjectPublicKeyInfo, &pub_key));

    ASSERT_RET_OK(cert_check_pubkey_and_usage(cert, pub_key, KEY_USAGE_CRL_SIGN, &flag));
    ASSERT_TRUE(flag == false);

cleanup:

    BA_FREE(buffer, pub_key);
}

static void utest_get_sn_2(void)
{
    ByteArray *sn = NULL;

    ASSERT_RET(RET_INVALID_PARAM, cert_get_sn(NULL, &sn));
    ASSERT_TRUE(sn == NULL);

cleanup:

    ba_free(sn);
}

static void utest_cert_get_non_critical_ext_oids_3(void)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;

    ASSERT_RET(RET_INVALID_PARAM, cert_get_non_critical_ext_oids(NULL, &oids, &cnt));
    ASSERT_TRUE(oids == NULL);
    ASSERT_TRUE(cnt == 0);

cleanup:

    return;
}

static void utest_cert_get_critical_ext_oids_3(void)
{
    OBJECT_IDENTIFIER_t **oids = NULL;
    size_t cnt = 0;

    ASSERT_RET(RET_INVALID_PARAM, cert_get_critical_ext_oids(NULL, &oids, &cnt));
    ASSERT_TRUE(oids == NULL);
    ASSERT_TRUE(cnt == 0);

cleanup:

    return;
}

static void utest_cert_init_by_sign_2(Certificate_t *cert)
{
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_sign(NULL, &cert->tbsCertificate, &cert->signatureAlgorithm, &cert->signature));
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_sign(cert, NULL, &cert->signatureAlgorithm, &cert->signature));
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_sign(cert, &cert->tbsCertificate, NULL, &cert->signature));
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_sign(cert, &cert->tbsCertificate, &cert->signatureAlgorithm, NULL));

cleanup:

    return;
}

static void utest_cert_init_by_adapter(Certificate_t *cert)
{
    Certificate_t *cert_tmp = cert_alloc();
    SignAdapter *sa = NULL;
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert_tmp, buffer));
    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert_tmp, &sa));

    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_adapter(NULL, &cert->tbsCertificate, sa));
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_adapter(cert, NULL, sa));
    ASSERT_RET(RET_INVALID_PARAM, cert_init_by_adapter(cert, &cert->tbsCertificate, NULL));

cleanup:

    sign_adapter_free(sa);
    BA_FREE(private_key, buffer);
    cert_free(cert_tmp);
}

void utest_cert(void)
{
    Certificate_t *cert = NULL;

    PR("%s\n", __FILE__);

    cert = load_test_data();

    if (cert) {
        utest_cert_encode(cert);
        utest_get_version(cert);
        utest_get_sn(cert);
        utest_get_not_before(cert);
        utest_get_not_after(cert);
        utest_get_tbs_info(cert);
        utest_get_aid(cert);
        utest_get_sign(cert);
        utest_get_key_usage(cert);
        utest_get_basic_constrains(cert);
        utest_is_ocsp_cert(cert);
        utest_get_spki(cert);
        utest_get_subj_key_id(cert);
        utest_get_auth_key_id(cert);
        utest_get_ext_value(cert);
        utest_get_tsp_url(cert);
        utest_cert_init_by_sign(cert);
        utest_cert_get_critical_ext_oids(cert);
        utest_cert_get_non_critical_ext_oids(cert);
        utest_cert_has_unsupported_critical_ext(cert);
        utest_cert_get_qc_statement_limit_3(cert);
        utest_cert_check_pubkey_and_usage(cert);
        utest_get_ext_value_3(cert);
        utest_cert_check_sid(cert);
        utest_cert_check_pubkey_and_usage_2(cert);
        utest_cert_init_by_sign_2(cert);
        utest_cert_init_by_adapter(cert);
    }

    utest_get_version_2();
    utest_is_ocsp_cert_2();
    utest_cert_get_qc_statement_limit();
    utest_cert_check_validity_encode();
    utest_cert_has_unsupported_critical_ext_2();
    utest_cert_get_critical_ext_oids_2();
    utest_cert_get_non_critical_ext_oids_2();
    utest_get_ext_value_2();
    utest_get_basic_constrains_2();
    utest_cert_get_qc_statement_limit_2();

#if defined(__LP64__) || defined(_WIN32)
    utest_cert_check_validity_with_date();
    utest_cert_check_validity_with_date_2();
    utest_cert_check_validity_with_date_3();
    utest_cert_get_not_before_2();
#endif

    utest_cert_get_basic_constrains_2();
    utest_cert_get_not_before_3();
    utest_cert_get_not_after_2();
    utest_cert_check_validity_with_date_4();
    utest_get_sn_2();
    utest_cert_get_non_critical_ext_oids_3();
    utest_cert_get_critical_ext_oids_3();

    cert_free(cert);
}
