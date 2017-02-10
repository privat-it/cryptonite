/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "asn1_utils.h"
#include "certification_request.h"
#include "cryptonite_manager.h"
#include "spki.h"
#include "aid.h"
#include "pkix_errors.h"
#include "ext.h"
#include "cert.h"

#define CERTIFICATION_REQUEST       "3082010530818C020100300D310B300906035504080C022E2E3076301006072A8648CE3D020106052B8104002203620004A687E44C321E298BB38132A987B4C89A467413CE7650665977C805FDBEC5B17D204B18C5EF0A8165D9BCEE121ADB6A3660E80120B3098AFE689203A64881C78B037B68E37877A1725E0902B31506BCC775079FFC076DD1A9C36EA7F78D977023A000300A06082A8648CE3D0403020368003065023100F6B6146A81D7A38EDA01E738F2BFF1FA5FEC6F163D382C31E03C0E9DAC29B375CA294D426A659C33BC27F03F89B301800230311DEA8503FF253826625C614BD9D3843C45EB84F362D1517CAEC5E4CF3736CB86D95E85413163F907005B564CFCBA5E"
#define CERTIFICATION_REQUEST_INFO  "30818C020100300D310B300906035504080C022E2E3076301006072A8648CE3D020106052B8104002203620004A687E44C321E298BB38132A987B4C89A467413CE7650665977C805FDBEC5B17D204B18C5EF0A8165D9BCEE121ADB6A3660E80120B3098AFE689203A64881C78B037B68E37877A1725E0902B31506BCC775079FFC076DD1A9C36EA7F78D977023A000"
#define CERTIFICATE_SIGN            "0368003065023100F6B6146A81D7A38EDA01E738F2BFF1FA5FEC6F163D382C31E03C0E9DAC29B375CA294D426A659C33BC27F03F89B301800230311DEA8503FF253826625C614BD9D3843C45EB84F362D1517CAEC5E4CF3736CB86D95E85413163F907005B564CFCBA5E"
#define CERTIFICATION_SPKI          "3076301006072A8648CE3D020106052B8104002203620004A687E44C321E298BB38132A987B4C89A467413CE7650665977C805FDBEC5B17D204B18C5EF0A8165D9BCEE121ADB6A3660E80120B3098AFE689203A64881C78B037B68E37877A1725E0902B31506BCC775079FFC076DD1A9C36EA7F78D977023"

static void test_creq_decode(CertificationRequest_t **creq)
{
    ByteArray *creq_ba = ba_alloc_from_le_hex_string(CERTIFICATION_REQUEST);

    ASSERT_NOT_NULL(creq_ba);
    ASSERT_NOT_NULL(*creq = creq_alloc());

    ASSERT_RET_OK(creq_decode(*creq, creq_ba));

cleanup:

    ba_free(creq_ba);
}

static void test_creq_encode(CertificationRequest_t *creq)
{
    ByteArray *creq_ba = ba_alloc_from_le_hex_string(CERTIFICATION_REQUEST);
    ByteArray *creq_curr_ba = NULL;

    ASSERT_NOT_NULL(creq_ba);
    ASSERT_RET_OK(creq_encode(creq, &creq_curr_ba));
    ASSERT_NOT_NULL(creq_curr_ba);

    ASSERT_EQUALS_BA(creq_ba, creq_curr_ba);

cleanup:

    BA_FREE(creq_ba, creq_curr_ba);
}

static void test_creq_get_aid(CertificationRequest_t *creq)
{
    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *act = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string("300A06082A8648CE3D040302");

    ASSERT_NOT_NULL(exp);

    ASSERT_RET_OK(creq_get_aid(creq, &aid));
    ASSERT_RET_OK(aid_encode(aid, &act));

    ASSERT_EQUALS_BA(act, exp);

cleanup:

    aid_free(aid);
    ba_free(act);
    ba_free(exp);
}

static void test_creq_get_cert_req_info(CertificationRequest_t *creq)
{
    CertificationRequestInfo_t *info = NULL;
    ByteArray *act = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(CERTIFICATION_REQUEST_INFO);

    ASSERT_NOT_NULL(exp);

    ASSERT_RET_OK(creq_get_info(creq, &info));
    ASSERT_RET_OK(asn_encode_ba(&CertificationRequestInfo_desc, info, &act));

    ASSERT_EQUALS_BA(act, exp);

cleanup:

    ASN_FREE(&CertificationRequestInfo_desc, info);
    ba_free(act);
    ba_free(exp);
}

static void test_creq_get_sign(CertificationRequest_t *creq)
{
    BIT_STRING_t *sign = NULL;
    ByteArray *act = NULL;
    ByteArray *exp = ba_alloc_from_le_hex_string(CERTIFICATE_SIGN);

    ASSERT_NOT_NULL(exp);

    ASSERT_RET_OK(creq_get_sign(creq, &sign));
    ASSERT_RET_OK(asn_encode_ba(&BIT_STRING_desc, sign, &act));

    ASSERT_EQUALS_BA(exp, act);

cleanup:

    ASN_FREE(&BIT_STRING_desc, sign);
    ba_free(act);
    ba_free(exp);

}

static void test_creq_verify(CertificationRequest_t *creq)
{
    ByteArray *spki_ba = ba_alloc_from_le_hex_string(CERTIFICATION_SPKI);
    SubjectPublicKeyInfo_t *spki = NULL;
    AlgorithmIdentifier_t *aid = NULL;
    VerifyAdapter *va = NULL;

    spki = spki_alloc();
    ASSERT_RET_OK(spki_decode(spki, spki_ba));

    ASSERT_RET_OK(creq_get_aid(creq, &aid));
    ASSERT_RET_OK(verify_adapter_init_by_spki(aid, spki, &va));
    ASSERT_RET_OK(creq_verify(creq, va));

cleanup:

    ba_free(spki_ba);
    spki_free(spki);
    aid_free(aid);
    verify_adapter_free(va);
}

static void test_creq_init_by_sign(CertificationRequest_t *creq)
{
    CertificationRequest_t *creq_tmp = creq_alloc();

    ASSERT_RET_OK(creq_init_by_sign(creq_tmp, &creq->certificationRequestInfo, &creq->signatureAlgorithm,
            &creq->signature));
    ASSERT_EQUALS_ASN(&CertificationRequestInfo_desc, &creq->certificationRequestInfo, &creq_tmp->certificationRequestInfo);
    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, &creq->signatureAlgorithm, &creq_tmp->signatureAlgorithm);
    ASSERT_EQUALS_ASN(&BIT_STRING_desc, &creq->signature, &creq_tmp->signature);

cleanup:

    creq_free(creq_tmp);
}

static void test_creq_get_attributes(CertificationRequest_t *creq)
{
    Attributes_t *ext = NULL;

    ASSERT_RET_OK(creq_get_attributes(creq, &ext));
    ASSERT_TRUE(ext->list.array == NULL);
    ASSERT_TRUE(ext->list.count == 0);

cleanup:

    ASN_FREE(&Attributes_desc, ext);

}

#undef CERTIFICATION_REQUEST
#undef CERTIFICATION_REQUEST_INFO
#undef CERTIFICATE_SIGN

static void test_creq_get_ext_by_oid(void)
{
    CertificationRequest_t *creq = creq_alloc();
    Extension_t *ext = NULL;

    ASSERT_RET(RET_PKIX_EXT_NOT_FOUND, creq_get_ext_by_oid(creq,
            oids_get_oid_numbers_by_id(OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID), &ext));
    ASSERT_TRUE(ext == NULL);
cleanup:

    creq_free(creq);
    ext_free(ext);
}

static void test_creq_init_by_adapter(void)
{
    CertificationRequest_t *creq = creq_alloc();
    CertificationRequest_t *creq_tmp = creq_alloc();
    VerifyAdapter *va = NULL;
    SignAdapter *sa = NULL;
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("4DDE173971C72162EF41B8FAF594A613A88A8E5FBB489544B80FF857013ACB1B");
    ByteArray *sign_ba =
            ba_alloc_from_le_hex_string("3060060b2a862402010101010301013051060d2a8624020101010103010102000440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904");
    ByteArray *alg_ba =
            ba_alloc_from_le_hex_string("3060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ByteArray *exp_sign_ba = ba_alloc_from_le_hex_string("300d060b2a86240201010101030101");
    ByteArray *creq_ba =
            ba_alloc_from_le_hex_string("308202D33082027B0201003082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC5790403240004214B3E3248B59687C272948F4198297767814601758A82A9C4D8E7925540C4AC2501A0818330818006092A864886F70D01090E31733071301C0603551D1104153013820563612E7561810A696E666F4063612E756130260603551D09041F301D301B060C2A8624020101010B01040101310B130932393234333131323830290603551D0E0422042026D492B7FC002341094D3D7534F2F1030CC6B1C67982FA6519E101F6E7C3239D300D060B2A8624020101010103010103430004407CF1AEDEDD9E758C94FA26A1F37D6FB6C9BD8EDD7AE502EBD4E9F8D1A0BB085B999EC746FD6F59BCAC423AF1473FE03B2F238A5BC667A246B2D66D9F17C6F845");
    ByteArray *cert_ba =
            ba_alloc_from_le_hex_string("308203FE308203A6A0030201020213123456789ABCDEFF0000123456789ABCDEFF00300D060B2A862402010101010301013082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C301E170D3133303132353230303030305A170D3233303132353230303030305A3082016331443042060355040A0C3BD09FD0B5D182D180D0BED0B220D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D18720D0A4D09ED09F311E301C060355040B0C15D09AD0B5D18069D0B2D0BDD0B8D186D182D0B2D0BE311C301A06035504030C13D09FD0B5D182D180D0BED0B220D0922ED09E2E3115301306035504040C0CD09FD0B5D182D180D0BED0B23130302E060355042A0C27D092D0B0D181D0B8D0BBD18C20D09ED0BBD0B5D0BAD181D0B0D0BDD0B4D180D0BED0B2D0B8D187311330110603550405130A39383334353637383132310B30090603550406130255413126302406035504070C1DD094D0BD69D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BA3129302706035504080C20D094D0BDD196D0BFD180D0BED0BFD0B5D182D180D0BED0B2D181D18CD0BAD0B0311F301D060355040C0C16D09FD196D0B4D0BFD180D0B8D194D0BCD0B5D186D18C3081883060060B2A862402010101010301013051060D2A8624020101010103010102060440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC5790403240004214B3E3248B59687C272948F4198297767814601758A82A9C4D8E7925540C4AC2501A3023000300D060B2A8624020101010103010103430004400059662E46C30ADA77EEE0AB91695C8657E8F325C0F400B5C9762D5AA7D4F30CA5A89C8F2F774D78C2D401C1EF51C6FFFC1AF43D800DE049EC2CC70693E7E907");
    AlgorithmIdentifier_t *signature_aid = aid_alloc();
    AlgorithmIdentifier_t *alg = aid_alloc();
    AlgorithmIdentifier_t *exp_signature_aid = aid_alloc();
    Certificate_t *cert = cert_alloc();

    ASSERT_RET_OK(creq_decode(creq_tmp, creq_ba));
    ASSERT_RET_OK(cert_decode(cert, cert_ba));
    ASSERT_RET_OK(aid_decode(signature_aid, sign_ba));
    ASSERT_RET_OK(aid_decode(alg, alg_ba));
    ASSERT_RET_OK(aid_decode(exp_signature_aid, exp_sign_ba));

    ASSERT_RET_OK(sign_adapter_init_by_aid(private_key, signature_aid, alg, &sa));

    ASSERT_RET_OK(creq_init_by_adapter(creq, &creq_tmp->certificationRequestInfo, sa));
    ASSERT_EQUALS_ASN(&CertificationRequestInfo_desc, &creq_tmp->certificationRequestInfo, &creq->certificationRequestInfo);
    ASSERT_EQUALS_ASN(&AlgorithmIdentifier_desc, exp_signature_aid, &creq->signatureAlgorithm);

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(creq_verify(creq, va));

cleanup:

    creq_free(creq);
    creq_free(creq_tmp);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    aid_free(signature_aid);
    aid_free(alg);
    aid_free(exp_signature_aid);
    cert_free(cert);
    BA_FREE(sign_ba, alg_ba, exp_sign_ba, private_key, creq_ba, cert_ba);
}

static void test_creq_init_by_sign_2(CertificationRequest_t *creq)
{
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_sign(NULL, &creq->certificationRequestInfo, &creq->signatureAlgorithm, &creq->signature));
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_sign(creq, NULL, &creq->signatureAlgorithm, &creq->signature));
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_sign(creq, &creq->certificationRequestInfo, NULL, &creq->signature));
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_sign(creq, &creq->certificationRequestInfo, &creq->signatureAlgorithm, NULL));

cleanup:

    return;
}

static void test_creq_init_by_adapter_2(CertificationRequest_t *creq)
{
    Certificate_t *cert_tmp = cert_alloc();
    SignAdapter *sa = NULL;
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert_tmp, buffer));
    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert_tmp, &sa));

    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_adapter(NULL, &creq->certificationRequestInfo, sa));
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_adapter(creq, NULL, sa));
    ASSERT_RET(RET_INVALID_PARAM, creq_init_by_adapter(creq, &creq->certificationRequestInfo, NULL));

cleanup:

    sign_adapter_free(sa);
    BA_FREE(private_key, buffer);
    cert_free(cert_tmp);
}

void utest_creq(void)
{
    CertificationRequest_t *creq = NULL;

    PR("%s\n", __FILE__);

    test_creq_decode(&creq);

    if (creq) {
        test_creq_encode(creq);
        test_creq_get_aid(creq);
        test_creq_get_cert_req_info(creq);
        test_creq_get_sign(creq);
        test_creq_verify(creq);
        test_creq_init_by_sign(creq);
        test_creq_get_attributes(creq);
        test_creq_get_ext_by_oid();
        test_creq_init_by_adapter();
        test_creq_init_by_sign_2(creq);
        test_creq_init_by_adapter_2(creq);
    }

    creq_free(creq);
}
