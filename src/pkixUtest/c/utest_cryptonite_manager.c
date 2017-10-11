/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "cryptonite_manager.h"
#include "pkix_errors.h"
#include "cert.h"
#include "spki.h"
#include "asn1_utils.h"
#include "aid.h"
#include "pkix_utils.h"

static void test_da_init_default(void)
{
    DigestAdapter *da = NULL;
    ByteArray *data = ba_alloc_by_len(0);
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_be_hex_string("82523E08D39CDD5F964285EB07F21291688C6B546DB241E9C152ED7F644EF75D");

    ASSERT_RET_OK(digest_adapter_init_default(&da));
    ASSERT_RET_OK(da->update(da, data));
    ASSERT_RET_OK(da->final(da, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da);
    BA_FREE(data, hash, exp_hash);
}

static void test_da_init_by_cert(void)
{
    DigestAdapter *da = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *data = ba_alloc_by_len(0);
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));
    ASSERT_NOT_NULL(da);
    ASSERT_RET_OK(da->update(da, data));
    ASSERT_RET_OK(da->final(da, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da);
    cert_free(cert);
    BA_FREE(data, hash, exp_hash, buffer);
}

static void test_da_init_by_cert_copy_with_alloc(void)
{
    DigestAdapter *da = NULL;
    DigestAdapter *da_copy = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *data = ba_alloc_by_len(0);
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));
    ASSERT_NOT_NULL(da);
    ASSERT_NOT_NULL(da_copy = digest_adapter_copy_with_alloc(da));
    digest_adapter_free(da);
    da = NULL;
    ASSERT_RET_OK(da_copy->update(da_copy, data));
    ASSERT_RET_OK(da_copy->final(da_copy, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da_copy);
    digest_adapter_free(da);
    cert_free(cert);
    BA_FREE(data, hash, exp_hash, buffer);
}

static void test_da_init_by_spki(void)
{
    DigestAdapter *da = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *data = ba_alloc_by_len(0);
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    ByteArray *buffer = NULL;
    DigestAlgorithmIdentifier_t *da_alg_id = NULL;
    ByteArray *da_alg_ba = NULL;

    /** SEQUENCE[1]
     *      OID1.2.804.2.1.1.1.1.2.1 ГОСТ 34.311-95
     */
    ByteArray *exp_da_alg_ba = ba_alloc_from_le_hex_string("300c060a2a862402010101010201");

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(digest_adapter_init_by_aid(&cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &da));
    ASSERT_RET_OK(da->update(da, data));
    ASSERT_RET_OK(da->final(da, &hash));
    ASSERT_EQUALS_BA(exp_hash, hash);

    /* da->get_alg() */
    ASSERT_RET_OK(da->get_alg(da, &da_alg_id));
    ASSERT_RET_OK(aid_encode(da_alg_id, &da_alg_ba));
    ASSERT_EQUALS_BA(exp_da_alg_ba, da_alg_ba);

cleanup:

    digest_adapter_free(da);
    cert_free(cert);
    aid_free(da_alg_id);
    BA_FREE(data, hash, exp_hash, buffer, da_alg_ba, exp_da_alg_ba);
}

static void test_get_gost28147_cipher_params(void)
{
    ByteArray *da_aid_ba = ba_alloc_from_le_hex_string("300c060a2a862402010101010201");
    ByteArray *sa_aid_ba =
            ba_alloc_from_le_hex_string("30820112060B2A86240201010101030101308201013081BC300F020201AF30090201010201030201050201010436F3CA40C669A4DA173149CA12C32DAE186B53AC6BC6365997DEAEAE8AD2D888F9BFD53401694EF9C4273D8CFE6DC28F706A0F4910CE0302363FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF04367C857C94C5433BFD991E17C22684065850A9A249ED7BC249AE5A4E878689F872EF7AD524082EC3038E9AEDE7BA6BA13381D979BA621A0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    OCTET_STRING_t *dke = NULL;
    ByteArray *act_dke_ba = NULL;
    ByteArray *exp_dke_ba =
            ba_alloc_from_le_hex_string("0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    AlgorithmIdentifier_t *aid = NULL;

    ASSERT_NOT_NULL(aid = aid_alloc());
    ASSERT_RET_OK(aid_decode(aid, da_aid_ba));
    ASSERT_RET_OK(get_gost28147_cipher_params(aid, &dke));
    ASSERT_RET_OK(asn_encode_ba(&OCTET_STRING_desc, dke, &act_dke_ba));
    ASSERT_EQUALS_BA(exp_dke_ba, act_dke_ba);

    BA_FREE(act_dke_ba);
    act_dke_ba = NULL;

    ASN_FREE(&OCTET_STRING_desc, dke);
    dke = NULL;

    ASSERT_RET_OK(aid_decode(aid, sa_aid_ba));
    ASSERT_RET_OK(get_gost28147_cipher_params(aid, &dke));
    ASSERT_RET_OK(asn_encode_ba(&OCTET_STRING_desc, dke, &act_dke_ba));
    ASSERT_EQUALS_BA(exp_dke_ba, act_dke_ba);

cleanup:

    BA_FREE(da_aid_ba, sa_aid_ba, act_dke_ba, exp_dke_ba);
    aid_free(aid);
    ASN_FREE(&OCTET_STRING_desc, dke);
}

static void test_sa_simple(void)
{
    SignAdapter *sa = NULL;
    SignAdapter *sa_copy = NULL;
    SignAdapter *sa_copy2 = NULL;
    ByteArray *buffer = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(sign_adapter_set_opt_level(sa, 0x0303));

    ASSERT_NOT_NULL(sa_copy = sign_adapter_copy_with_alloc(sa));
    ASSERT_RET_OK(sign_adapter_set_opt_level(sa, 0x3030));

    ASSERT_NOT_NULL(sa_copy2 = sign_adapter_copy_with_alloc(sa));

cleanup:

    ba_free(private_key);
    sign_adapter_free(sa);
    sign_adapter_free(sa_copy);
    sign_adapter_free(sa_copy2);
    ba_free(buffer);
    cert_free(cert);
}
static void test_sa(void)
{
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    SignAdapter *sa = NULL;
    SignAdapter *sa_copy = NULL;
    VerifyAdapter *va = NULL;
    /* SEQUENCE OID 1.2.804.2.1.1.1.1.2.1 (ГОСТ 34.311-95) */
    ByteArray *exp_digest_aid_bytes = ba_alloc_from_le_hex_string("300c060a2a862402010101010201");
    ByteArray *act_digest_aid_bytes = NULL;
    AlgorithmIdentifier_t *digest_aid = NULL;
    /* SEQUENCE OID 1.2.804.2.1.1.1.1.3.1.1 (ДСТУ 4145-2002) */
    ByteArray *exp_sign_aid_bytes = ba_alloc_from_le_hex_string("300d060b2a86240201010101030101");
    ByteArray *act_sign_aid_bytes = NULL;
    AlgorithmIdentifier_t *sign_aid = NULL;
    ByteArray *exp_pub_key_bytes =
            ba_alloc_from_le_hex_string("3081883060060b2a862402010101010301013051060d2a86240201010101030101020"
                                                "60440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17"
                                                "f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac5790403240"
                                                "00421d7b049230f30fd10c53cb78a347efee8cfbe04f0cf1660143af44537e076834001");
    ByteArray *act_pub_key_bytes = NULL;
    SubjectPublicKeyInfo_t *pub_key = NULL;
    bool has_cert = false;
    ByteArray *data = ba_alloc_from_le_hex_string("00");
    ByteArray *hash = ba_alloc_from_be_hex_string("AA090E826B0E3DB93E4F613D2F39E3DC6C602CB543918489E1473197FC027A26");
    ByteArray *sign = NULL;
    int ret;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    /* sa from sign_adapter_init_by_alg() */
    ASSERT_RET_OK(sign_adapter_init_by_aid(private_key, &cert->signatureAlgorithm,
                                           &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &sa));
    ret = sa->get_cert(sa, &act_cert);
    ASSERT_TRUE(ret == RET_PKIX_NO_CERTIFICATE);

    ASSERT_RET_OK(sa->get_digest_alg(sa, &digest_aid));
    ASSERT_RET_OK(aid_encode(digest_aid, &act_digest_aid_bytes));
    ASSERT_EQUALS_BA(exp_digest_aid_bytes, act_digest_aid_bytes);

    ASSERT_RET_OK(sa->get_sign_alg(sa, &sign_aid));
    ASSERT_RET_OK(aid_encode(sign_aid, &act_sign_aid_bytes));
    ASSERT_EQUALS_BA(exp_sign_aid_bytes, act_sign_aid_bytes);

    ASSERT_RET_OK(sa->get_pub_key(sa, &pub_key));
    ASSERT_RET_OK(spki_encode(pub_key, &act_pub_key_bytes));
    ASSERT_EQUALS_BA(exp_pub_key_bytes, act_pub_key_bytes);

    ASSERT_RET_OK(sa->has_cert(sa, &has_cert));
    ASSERT_TRUE(!has_cert);

    /* Verify sa results. */
    ASSERT_RET_OK(sa->sign_data(sa, data, &sign));
    ASSERT_RET_OK(va->verify_hash(va, hash, sign));
    ba_free(sign);
    sign = NULL;

    ASSERT_RET_OK(sa->sign_hash(sa, hash, &sign));
    ASSERT_RET_OK(va->verify_data(va, data, sign));

    sign_adapter_free(sa);
    sa = NULL;
    aid_free(digest_aid);
    digest_aid = NULL;
    aid_free(sign_aid);
    sign_aid = NULL;
    spki_free(pub_key);
    pub_key = NULL;

    BA_FREE(sign, act_sign_aid_bytes, act_pub_key_bytes, act_digest_aid_bytes);
    sign = NULL;
    pub_key = NULL;
    act_sign_aid_bytes = NULL;
    act_digest_aid_bytes = NULL;
    act_pub_key_bytes = NULL;

    /* sa from sign_adapter_init_by_cert() */

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_NOT_NULL(sa_copy = sign_adapter_copy_with_alloc(sa));
    sign_adapter_free(sa);
    sa = NULL;
    ASSERT_RET_OK(sa_copy->get_cert(sa_copy, &act_cert));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(sa_copy->get_digest_alg(sa_copy, &digest_aid));
    ASSERT_RET_OK(aid_encode(digest_aid, &act_digest_aid_bytes));
    ASSERT_EQUALS_BA(exp_digest_aid_bytes, act_digest_aid_bytes);

    ASSERT_RET_OK(sa_copy->get_sign_alg(sa_copy, &sign_aid));
    ASSERT_RET_OK(aid_encode(sign_aid, &act_sign_aid_bytes));
    ASSERT_EQUALS_BA(exp_sign_aid_bytes, act_sign_aid_bytes);

    ASSERT_RET_OK(sa_copy->get_pub_key(sa_copy, &pub_key));
    ASSERT_RET_OK(spki_encode(pub_key, &act_pub_key_bytes));
    ASSERT_EQUALS_BA(exp_pub_key_bytes, act_pub_key_bytes);

    ASSERT_RET_OK(sa_copy->has_cert(sa_copy, &has_cert));
    ASSERT_TRUE(has_cert);

    /* Verify sa results. */
    ASSERT_RET_OK(sa_copy->sign_data(sa_copy, data, &sign));
    ASSERT_RET_OK(va->verify_hash(va, hash, sign));
    ba_free(sign);
    sign = NULL;

    ASSERT_RET_OK(sa_copy->sign_hash(sa_copy, hash, &sign));
    ASSERT_RET_OK(va->verify_data(va, data, sign));
    ba_free(sign);
    sign = NULL;

cleanup:

    BA_FREE(private_key, buffer, exp_digest_aid_bytes, act_digest_aid_bytes, exp_sign_aid_bytes, act_sign_aid_bytes,
            act_pub_key_bytes, exp_pub_key_bytes, sign, data, hash);
    sign_adapter_free(sa);
    sign_adapter_free(sa_copy);
    verify_adapter_free(va);
    cert_free(cert);
    cert_free(act_cert);
    aid_free(digest_aid);
    aid_free(sign_aid);
    spki_free(pub_key);
}

static void test_sa_with_wrong_priv_pub_key(void)
{
    ByteArray *private_key_with_wrong_value =
            ba_alloc_from_le_hex_string("1B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *private_key_with_bad_len =
            ba_alloc_from_le_hex_string("12121B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    ByteArray *buffer = NULL;
    Certificate_t *cert = cert_alloc();
    SignAdapter *sa = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    /* sa from sign_adapter_init_by_alg() */
    ASSERT_RET_OK(sign_adapter_init_by_aid(private_key_with_wrong_value, &cert->signatureAlgorithm,
            &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &sa));
    sign_adapter_free(sa);
    sa = NULL;

    ASSERT_RET(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS, sign_adapter_init_by_aid(private_key_with_bad_len,
            &cert->signatureAlgorithm, &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &sa));

    /* sa from sign_adapter_init_by_cert() */
    ASSERT_RET(RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV, sign_adapter_init_by_cert(private_key_with_wrong_value, cert,
            &sa));
    ASSERT_RET(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS, sign_adapter_init_by_cert(private_key_with_bad_len, cert, &sa));

cleanup:

    BA_FREE(private_key_with_bad_len, private_key_with_wrong_value, buffer);
    cert_free(cert);

    return;
}

static void test_sa_ecdsa_with_wrong_priv_pub_key(void)
{
    ByteArray *private_key_with_wrong_value =
            ba_alloc_from_le_hex_string("66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32AE24A37407D01D32AFFFF");
    ByteArray *private_key_with_bad_len =
            ba_alloc_from_le_hex_string("12121B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32AE24A37407D01D32AFFFF");
    ByteArray *buffer = NULL;
    Certificate_t *cert = cert_alloc();
    SignAdapter *sa = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ecdsa_cert.crt", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    /* sa from sign_adapter_init_by_alg() */
    ASSERT_RET_OK(sign_adapter_init_by_aid(private_key_with_wrong_value, &cert->signatureAlgorithm,
            &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &sa));
    sign_adapter_free(sa);
    sa = NULL;

    ASSERT_RET(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS, sign_adapter_init_by_aid(private_key_with_bad_len,
            &cert->signatureAlgorithm, &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &sa));

    /* sa from sign_adapter_init_by_cert() */
    ASSERT_RET(RET_PKIX_PUB_KEY_NOT_CORRESPOND_FOR_PRIV, sign_adapter_init_by_cert(private_key_with_wrong_value, cert,
            &sa));
    ASSERT_RET(RET_PKIX_PRIV_KEY_NOT_CORRESPOND_FOR_PARAMS, sign_adapter_init_by_cert(private_key_with_bad_len, cert, &sa));

cleanup:

    BA_FREE(private_key_with_bad_len, private_key_with_wrong_value, buffer);
    cert_free(cert);

    return;
}

static void test_va_init_by_cert(void)
{
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    SubjectPublicKeyInfo_t *act_pub_key_info = NULL;
    DigestAlgorithmIdentifier_t *digest_alg_id = NULL;
    ByteArray *buffer = NULL;
    ByteArray *data = NULL;
    ByteArray *sign = NULL;
    bool has_cert;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_signed_attr.der", &data));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_sign.dat", &sign));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_sign.cer", &buffer));

    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_TRUE(va != NULL);

    ASSERT_RET_OK(va->has_cert(va, &has_cert));
    ASSERT_TRUE(has_cert);

    ASSERT_RET_OK(va->get_cert(va, &act_cert));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(va->get_pub_key(va, &act_pub_key_info));
    ASSERT_EQUALS_ASN(&SubjectPublicKeyInfo_desc, &cert->tbsCertificate.subjectPublicKeyInfo, act_pub_key_info);

    ASSERT_RET_OK(va->get_digest_alg(va, &digest_alg_id));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(va->verify_data(va, data, sign));

cleanup:

    verify_adapter_free(va);

    cert_free(cert);
    cert_free(act_cert);
    spki_free(act_pub_key_info);
    aid_free(digest_alg_id);

    BA_FREE(buffer, data, sign);
}

static void test_va_init_by_cert_copy_with_alloc(void)
{
    VerifyAdapter *va = NULL;
    VerifyAdapter *va_copy = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    SubjectPublicKeyInfo_t *act_pub_key_info = NULL;
    DigestAlgorithmIdentifier_t *digest_alg_id = NULL;
    ByteArray *buffer = NULL;
    ByteArray *data = NULL;
    ByteArray *sign = NULL;
    bool has_cert;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_signed_attr.der", &data));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_sign.dat", &sign));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_sign.cer", &buffer));

    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(verify_adapter_set_opt_level(va, 0x0505));

    ASSERT_NOT_NULL(va_copy = verify_adapter_copy_with_alloc(va));
    verify_adapter_free(va);
    va = NULL;
    ASSERT_RET_OK(va_copy->has_cert(va_copy, &has_cert));
    ASSERT_TRUE(has_cert);

    ASSERT_RET_OK(va_copy->get_cert(va_copy, &act_cert));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(va_copy->get_pub_key(va_copy, &act_pub_key_info));
    ASSERT_EQUALS_ASN(&SubjectPublicKeyInfo_desc, &cert->tbsCertificate.subjectPublicKeyInfo, act_pub_key_info);

    ASSERT_RET_OK(va_copy->get_digest_alg(va_copy, &digest_alg_id));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(va_copy->verify_data(va_copy, data, sign));

cleanup:

    verify_adapter_free(va);
    verify_adapter_free(va_copy);

    cert_free(cert);
    cert_free(act_cert);
    spki_free(act_pub_key_info);
    aid_free(digest_alg_id);

    BA_FREE(buffer, data, sign);
}

static void test_va_init_by_spki(void)
{
    int ret = RET_OK;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *bad_cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    SubjectPublicKeyInfo_t *act_pub_key_info = NULL;
    DigestAlgorithmIdentifier_t *digest_alg_id = NULL;
    ByteArray *data = NULL;
    ByteArray *sign = NULL;
    ByteArray *buffer = NULL;
    ByteArray *act_digest_aid_bytes = NULL;
    ByteArray *exp_digest_aid_bytes = ba_alloc_from_le_hex_string("300c060a2a862402010101010201");
    bool has_cert;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_signed_attr.der", &data));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_sign.dat", &sign));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_sign.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(verify_adapter_init_by_spki(&cert->tbsCertificate.signature, &cert->tbsCertificate.subjectPublicKeyInfo,
            &va));
    ASSERT_TRUE(va != NULL);

    ASSERT_RET_OK(va->has_cert(va, &has_cert));
    ASSERT_TRUE(!has_cert);

    ret = va->get_cert(va, &act_cert);
    ASSERT_TRUE(ret == RET_PKIX_NO_CERTIFICATE);

    ASSERT_RET_OK(va->get_pub_key(va, &act_pub_key_info));
    ASSERT_EQUALS_ASN(&SubjectPublicKeyInfo_desc, &cert->tbsCertificate.subjectPublicKeyInfo, act_pub_key_info);

    ASSERT_RET_OK(va->get_digest_alg(va, &digest_alg_id));
    ASSERT_RET_OK(aid_encode(digest_alg_id, &act_digest_aid_bytes));
    ASSERT_EQUALS_BA(exp_digest_aid_bytes, act_digest_aid_bytes);

    ASSERT_RET_OK(va->verify_data(va, data, sign));

    BA_FREE(buffer);
    buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/83C539C16F20B8257B0F298E20141840.crt", &buffer));
    ASSERT_RET_OK(cert_decode(bad_cert, buffer));

    ret = va->set_cert(va, bad_cert);
    ASSERT_TRUE(ret == RET_PKIX_NO_CERTIFICATE);

    ASSERT_RET_OK(va->set_cert(va, cert));
    ASSERT_RET_OK(va->get_cert(va, &act_cert));

cleanup:

    verify_adapter_free(va);

    cert_free(cert);
    cert_free(act_cert);
    cert_free(bad_cert);
    spki_free(act_pub_key_info);
    aid_free(digest_alg_id);

    BA_FREE(buffer, data, sign, act_digest_aid_bytes, exp_digest_aid_bytes);
}

void test_get_gost28147_params_by_os(void)
{
    ByteArray *sbox_os_ba =
            ba_alloc_from_le_hex_string("0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ByteArray *sbox_ba_expected =
            ba_alloc_from_le_hex_string("A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC57904");
    ByteArray *sbox_ba = NULL;
    OCTET_STRING_t *sbox_os = NULL;
    Gost28147Ctx *params = NULL;

    ASSERT_NOT_NULL(sbox_os = asn_decode_ba_with_alloc(&OCTET_STRING_desc, sbox_os_ba));
    ASSERT_RET_OK(get_gost28147_params_by_os(sbox_os, &params));
    ASSERT_RET_OK(gost28147_get_compress_sbox(params, &sbox_ba));
    ASSERT_EQUALS_BA(sbox_ba_expected, sbox_ba);

cleanup:

    ba_free(sbox_os_ba);
    ba_free(sbox_ba_expected);
    ba_free(sbox_ba);
    ASN_FREE(&OCTET_STRING_desc, sbox_os);
    gost28147_free(params);
}

static void test_da_init_by_cert_2(void)
{
    DigestAdapter *da = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *data = ba_alloc_by_len(0);
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ecdsa_cert.crt", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));
    ASSERT_NOT_NULL(da);
    ASSERT_RET_OK(da->update(da, data));
    ASSERT_RET_OK(da->final(da, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da);
    cert_free(cert);
    BA_FREE(data, hash, exp_hash, buffer);
}

static void test_cipher_adapter_copy_with_alloc(void)
{
    AlgorithmIdentifier_t *cipher_aid = NULL;
    AlgorithmIdentifier_t *act_cipher_aid = NULL;
    CipherAdapter *ca = NULL;
    CipherAdapter *ca_copy = NULL;
    Certificate_t *cert = NULL;
    PrngCtx *prng = NULL;
    ByteArray *seed = ba_alloc_by_len(40);
    ByteArray *buffer = NULL;
    OBJECT_IDENTIFIER_t *cipher_oid = NULL;
    ByteArray *session_secret_key = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("00");
    ByteArray *encrypted_data = NULL;
    ByteArray *decrypted_data = NULL;

    ASSERT_RET_OK(ba_set(seed, 0x20));
    ASSERT_RET_OK(pkix_create_oid(oids_get_oid_numbers_by_id(OID_GOST28147_OFB_ID), &cipher_oid));
    ASSERT_NOT_NULL(prng = prng_alloc(PRNG_MODE_DSTU, seed));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_NOT_NULL(cert = cert_alloc());
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(get_gost28147_aid(prng, cipher_oid, cert, &cipher_aid));
    ASSERT_RET_OK(cipher_adapter_init(cipher_aid, &ca));
    ASSERT_NOT_NULL(ca);
    ASSERT_NOT_NULL(ca_copy = cipher_adapter_copy_with_alloc(ca));

    ASSERT_RET_OK(ca_copy->get_alg(ca, &act_cipher_aid));
    ASSERT_EQUALS_ASN(get_AlgorithmIdentifier_desc(), cipher_aid, act_cipher_aid);

    ASSERT_RET_OK(gost28147_generate_key(prng, &session_secret_key));
    ASSERT_RET_OK(ca_copy->encrypt(ca_copy, session_secret_key, data, &encrypted_data));
    ASSERT_RET_OK(ca_copy->decrypt(ca_copy, session_secret_key, encrypted_data, &decrypted_data));
    ASSERT_EQUALS_BA(data, decrypted_data);

cleanup:

    BA_FREE(buffer, seed, session_secret_key, data, encrypted_data, decrypted_data);
    cipher_adapter_free(ca);
    cipher_adapter_free(ca_copy);
    aid_free(cipher_aid);
    aid_free(act_cipher_aid);
    cert_free(cert);
    prng_free(prng);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, cipher_oid);
}

static void test_dh_adapter_copy_with_alloc(void)
{
    ByteArray *private_key =
            ba_alloc_from_le_hex_string("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;
    DhAdapter *dha = NULL;
    DhAdapter *dha_copy = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/certificate257.cer", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(dh_adapter_init(private_key, &cert->tbsCertificate.subjectPublicKeyInfo.algorithm, &dha));

    ASSERT_NOT_NULL(dha_copy = dh_adapter_copy_with_alloc(dha));

cleanup:

    BA_FREE(buffer, private_key);
    cert_free(cert);
    dh_adapter_free(dha);
    dh_adapter_free(dha_copy);
}

static void test_da_init_by_aid_copy_with_alloc(void)
{
    DigestAdapter *da = NULL;
    DigestAdapter *da_copy = NULL;
    AlgorithmIdentifier_t *aid = aid_alloc();
    const OidNumbers *oids = NULL;
    ByteArray *data = ba_alloc_from_str("Cryptonite");
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("a7eaa036beb43131b0818c2c324e52310763c95f91dc91234a395b0f1a0ebdd8abe491e426ada2c4700231258347631ac94fa01e43150246cc5d824ac88e420b");

    ASSERT_NOT_NULL(oids = oids_get_oid_numbers_by_id(OID_PKI_SHA512_ID));
    ASSERT_RET_OK(aid_init_by_oid(aid, oids));

    ASSERT_RET_OK(digest_adapter_init_by_aid(aid, &da));
    ASSERT_NOT_NULL(da);

    ASSERT_NOT_NULL(da_copy = digest_adapter_copy_with_alloc(da));

    ASSERT_RET_OK(da_copy->update(da_copy, data));
    ASSERT_RET_OK(da_copy->final(da_copy, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da);
    digest_adapter_free(da_copy);
    aid_free(aid);
    BA_FREE(data, hash, exp_hash);
}

static void test_da_init_by_aid_copy_with_alloc_2(void)
{
    DigestAdapter *da = NULL;
    DigestAdapter *da_copy = NULL;
    AlgorithmIdentifier_t *aid = aid_alloc();
    const OidNumbers *oids = NULL;
    ByteArray *data = ba_alloc_from_le_hex_string("3b46736d559bd4e0c2c1b2553a33ad3c6cf23cac998d3d0c0e8fa4b19bca06f2f386db2dcff9dca4f40ad8f561ffc308b46c5f31a7735b5fa7e0f9e6cb512e63d7eea05538d66a75cd0d4234b5ccf6c1715ccaaf9cdc0a2228135f716ee9bdee7fc13ec27a03a6d11c5c5b3685f51900b1337153bc6c4e8f52920c33fa37f4e7");
    ByteArray *hash = NULL;
    ByteArray *exp_hash = ba_alloc_from_le_hex_string("58429e8f371f9e1d69a5bf96a554d627cfd5485c");

    ASSERT_NOT_NULL(oids = oids_get_oid_numbers_by_id(OID_PKI_SHA1_ID));
    ASSERT_RET_OK(aid_init_by_oid(aid, oids));

    ASSERT_RET_OK(digest_adapter_init_by_aid(aid, &da));
    ASSERT_NOT_NULL(da);

    ASSERT_NOT_NULL(da_copy = digest_adapter_copy_with_alloc(da));

    ASSERT_RET_OK(da_copy->update(da_copy, data));
    ASSERT_RET_OK(da_copy->final(da_copy, &hash));

    ASSERT_EQUALS_BA(exp_hash, hash);

cleanup:

    digest_adapter_free(da);
    digest_adapter_free(da_copy);
    aid_free(aid);
    BA_FREE(data, hash, exp_hash);
}

static void test_va_init_by_cert_2(void)
{
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    Certificate_t *act_cert = NULL;
    SubjectPublicKeyInfo_t *act_pub_key_info = NULL;
    DigestAlgorithmIdentifier_t *act_digest_alg_id = NULL;
    DigestAlgorithmIdentifier_t *exp_digest_alg_id = aid_alloc();
    AlgorithmIdentifier_t *act_sign_alg_id = NULL;
    const OidNumbers *oids = NULL;
    ByteArray *buffer = NULL;
    bool has_cert;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ecdsa_cert.crt", &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_TRUE(va != NULL);

    ASSERT_RET_OK(va->has_cert(va, &has_cert));
    ASSERT_TRUE(has_cert);

    ASSERT_RET_OK(va->get_cert(va, &act_cert));
    ASSERT_EQUALS_ASN(get_Certificate_desc(), cert, act_cert);

    ASSERT_RET_OK(va->get_pub_key(va, &act_pub_key_info));
    ASSERT_EQUALS_ASN(&SubjectPublicKeyInfo_desc, &cert->tbsCertificate.subjectPublicKeyInfo, act_pub_key_info);

    ASSERT_NOT_NULL(oids = oids_get_oid_numbers_by_id(OID_PKI_SHA256_ID));
    ASSERT_RET_OK(aid_init_by_oid(exp_digest_alg_id, oids));
    ASSERT_RET_OK(va->get_digest_alg(va, &act_digest_alg_id));
    ASSERT_EQUALS_ASN(get_DigestAlgorithmIdentifier_desc(), exp_digest_alg_id, act_digest_alg_id);

    ASSERT_RET_OK(va->get_sign_alg(va, &act_sign_alg_id));
    ASSERT_EQUALS_ASN(get_AlgorithmIdentifier_desc(), &cert->signatureAlgorithm, act_sign_alg_id);

cleanup:

    verify_adapter_free(va);
    cert_free(cert);
    cert_free(act_cert);
    spki_free(act_pub_key_info);
    aid_free(act_digest_alg_id);
    aid_free(exp_digest_alg_id);
    aid_free(act_sign_alg_id);
    ba_free(buffer);
}

void utest_cryptonite_manager(void)
{
    PR("%s\n", __FILE__);

    test_da_init_default();
    test_da_init_by_cert();
    test_da_init_by_spki();
    test_sa_simple();
    test_sa();
    test_sa_with_wrong_priv_pub_key();
    test_sa_ecdsa_with_wrong_priv_pub_key();
    test_va_init_by_cert();
    test_va_init_by_spki();
    test_get_gost28147_params_by_os();
    test_get_gost28147_cipher_params();
    test_da_init_by_cert_2();
    test_da_init_by_cert_copy_with_alloc();
    test_va_init_by_cert_copy_with_alloc();
    test_dh_adapter_copy_with_alloc();
    test_da_init_by_aid_copy_with_alloc();
    test_da_init_by_aid_copy_with_alloc_2();
    test_va_init_by_cert_2();
    test_cipher_adapter_copy_with_alloc();
}
