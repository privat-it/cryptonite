/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "signer_info.h"
#include "cert.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "pkix_errors.h"
#include "cryptonite_manager.h"

static SignerInfo_t *sinfo = NULL;

static void load_test_data(void)
{
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/cms_sign/SignInfo_1.dat", &encoded));

    ASSERT_NOT_NULL(sinfo = sinfo_alloc());

    ASSERT_RET_OK(sinfo_decode(sinfo, encoded));

cleanup:

    ba_free(encoded);
}

static void test_sinfo_encode(void)
{
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/cms_sign/SignInfo_1.dat", &decoded));

    ASSERT_RET_OK(sinfo_encode(sinfo, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_EQUALS_BA(decoded, encoded);
cleanup:
    BA_FREE(decoded, encoded);
}

void test_sinfo_get_version(void)
{
    int version;

    ASSERT_RET_OK(sinfo_get_version(sinfo, &version));
    ASSERT_TRUE(version == 1);

cleanup:
    return;
}

void test_sinfo_get_signer_id(void)
{
    SignerIdentifier_t *sid = NULL;

    ASSERT_RET_OK(sinfo_get_signer_id(sinfo, &sid));
    ASSERT_EQUALS_ASN(&SignerIdentifier_desc, &sinfo->sid, sid);

cleanup:
    ASN_FREE(&SignerIdentifier_desc, sid);
}

void test_sinfo_get_signed_attrs(void)
{
    Attributes_t *attrs = NULL;

    ASSERT_RET_OK(sinfo_get_signed_attrs(sinfo, &attrs));
    ASSERT_EQUALS_ASN(&Attributes_desc, sinfo->signedAttrs, attrs);
cleanup:
    ASN_FREE(&Attributes_desc, attrs);
}

void test_sinfo_has_signed_attrs(void)
{
    bool answ;

    ASSERT_RET_OK(sinfo_has_signed_attrs(sinfo, &answ));
    ASSERT_TRUE(answ == true);

cleanup:
    return;
}

void test_sinfo_has_unsigned_attrs(void)
{
    bool answ;

    ASSERT_RET_OK(sinfo_has_unsigned_attrs(sinfo, &answ));
    ASSERT_TRUE(answ == false);

cleanup:
    return;
}

void test_sinfo_get_signed_attr_by_idx(void)
{
    Attribute_t *attr = NULL;

    ASSERT_RET_OK(sinfo_get_signed_attr_by_idx(sinfo, 0, &attr));
    ASSERT_EQUALS_ASN(&Attribute_desc, sinfo->signedAttrs->list.array[0], attr);

cleanup:
    ASN_FREE(&Attribute_desc, attr);
}

void test_sinfo_get_signed_attr_by_oid(void)
{
    Attribute_t *attr = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;

    ASSERT_RET_OK(pkix_create_oid(oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID), &oid));

    ASSERT_RET_OK(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));
    ASSERT_EQUALS_ASN(&Attribute_desc, sinfo->signedAttrs->list.array[1], attr);

cleanup:

    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
}

void test_sinfo_get_unsigned_attrs(void)
{
    Attributes_t *attrs = NULL;

    ASSERT_RET_OK(sinfo_get_unsigned_attrs(sinfo, &attrs));
    ASSERT_TRUE(attrs == NULL);

cleanup:

    ASN_FREE(&Attributes_desc, attrs);
}

static void test_sinfo_add_unsigned_attr(void)
{
    ByteArray *unsigned_attr =
            ba_alloc_from_le_hex_string("3045060B2A864886F70D01091002153136303430323030300C060A2A86240201010101020104203A9723649ADEECE0670A57BE0062C1CFC3C7046232318021866353B4B2837DAB");
    Attribute_t *unsigned_attribute = NULL;
    Attributes_t *unsigned_attributes = NULL;
    bool has_unsigned_attrs;

    ASSERT_NOT_NULL(unsigned_attribute = asn_decode_ba_with_alloc(&Attribute_desc, unsigned_attr));
    ASSERT_RET_OK(sinfo_add_unsigned_attr(sinfo, unsigned_attribute));
    ASSERT_RET_OK(sinfo_has_unsigned_attrs(sinfo, &has_unsigned_attrs));
    ASSERT_TRUE(has_unsigned_attrs == true);
    ASSERT_RET_OK(sinfo_get_unsigned_attrs(sinfo, &unsigned_attributes));
    ASSERT_TRUE(unsigned_attributes->list.count == 1);
    ASSERT_EQUALS_ASN(&Attribute_desc, unsigned_attribute, unsigned_attributes->list.array[0]);

cleanup:

    ba_free(unsigned_attr);
    ASN_FREE(&Attribute_desc, unsigned_attribute);
    ASN_FREE(&Attributes_desc, unsigned_attributes);
}

void test_sinfo_get_unsigned_attrs_2(void)
{
    Attributes_t *attrs = NULL;
    ByteArray *exp_unsigned_attr =
            ba_alloc_from_le_hex_string("3045060B2A864886F70D01091002153136303430323030300C060A2A86240201010101020104203A9723649ADEECE0670A57BE0062C1CFC3C7046232318021866353B4B2837DAB");
    ByteArray *act_unsigned_attr = NULL;
    Attribute_t *attr = NULL;

    ASSERT_RET_OK(sinfo_get_unsigned_attrs(sinfo, &attrs));
    ASSERT_TRUE(attrs->list.count == 1);
    ASSERT_RET_OK(asn_encode_ba(&Attribute_desc, attrs->list.array[0], &act_unsigned_attr));
    ASSERT_EQUALS_BA(exp_unsigned_attr, act_unsigned_attr);

    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sinfo_get_signed_attr_by_idx(sinfo, sinfo->signedAttrs->list.count, &attr));
    ASSERT_RET(RET_PKIX_OUT_OF_BOUND_ERROR, sinfo_get_unsigned_attr_by_idx(sinfo, sinfo->unsignedAttrs->list.count, &attr));

cleanup:

    BA_FREE(exp_unsigned_attr, act_unsigned_attr);
    ASN_FREE(&Attributes_desc, attrs);
    ASN_FREE(&Attribute_desc, attr);
}

static void test_sinfo_get_attrs(void)
{
    SignerInfo_t *sinfo = sinfo_alloc();
    Attributes_t *attrs = NULL;
    Attribute_t *attr = NULL;
    int format;

    ASSERT_RET_OK(sinfo_get_signed_attrs(sinfo, &attrs));
    ASSERT_TRUE(attrs == NULL);

    ASSERT_RET_OK(sinfo_get_signed_attr_by_idx(sinfo, 0, &attr));
    ASSERT_TRUE(attr == NULL);

    ASSERT_RET_OK(sinfo_get_unsigned_attr_by_idx(sinfo, 0, &attr));
    ASSERT_TRUE(attr == NULL);

    ASSERT_RET_OK(sinfo_get_format(sinfo, &format));
    ASSERT_TRUE(format == 0);

cleanup:

    sinfo_free(sinfo);
    ASN_FREE(&Attributes_desc, attrs);
    ASN_FREE(&Attribute_desc, attr);
}

static void test_sinfo_verify(void)
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

    ASSERT_RET(RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER, sinfo_verify(sinfo, da, va, buffer));
    ASSERT_RET(RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER, sinfo_verify_without_data(sinfo, da, va));
    ASSERT_RET(RET_PKIX_VERIFY_FAILED, verify_core(sinfo, da, va, buffer));
    ASSERT_RET(RET_PKIX_SDATA_VERIFY_CERT_V2_FAILED, sinfo_verify_signing_cert_v2(sinfo, da, cert));

cleanup:

    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
    digest_adapter_free(da);
}

static void test_sinfo_verify_signing_cert_v2(void)
{
    SignerInfo_t *sinfo_tmp = sinfo_alloc();
    DigestAdapter *da = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;
    Attribute_t *sign_attr = NULL;
    int format;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));

    ASSERT_RET(RET_INVALID_PARAM, sinfo_verify_signing_cert_v2(sinfo_tmp, da, cert));

    ASSERT_NOT_NULL(sign_attr = asn_copy_with_alloc(&Attribute_desc, sinfo->signedAttrs->list.array[1]));
    ASSERT_ASN_ALLOC(sinfo_tmp->signedAttrs);

    ASN_SET_ADD(sinfo_tmp->signedAttrs, sign_attr);

    ASSERT_RET(RET_PKIX_SDATA_NO_CERT_V2, sinfo_verify_signing_cert_v2(sinfo_tmp, da, cert));

    ASSERT_RET_OK(sinfo_get_format(sinfo_tmp, &format));
    ASSERT_TRUE(format == 0);

cleanup:

    ba_free(buffer);
    cert_free(cert);
    digest_adapter_free(da);
    sinfo_free(sinfo_tmp);
}

static void test_sinfo_get_signed_attrs_2(void)
{
    Attributes_t *attrs = NULL;

    ASSERT_RET(RET_INVALID_PARAM, sinfo_get_signed_attrs(NULL, &attrs));
    ASSERT_TRUE(attrs == NULL);

cleanup:

    ASN_FREE(&Attributes_desc, attrs);
}

static void test_sinfo_add_unsigned_attr_2(void)
{
    ByteArray *unsigned_attr =
            ba_alloc_from_le_hex_string("3045060B2A864886F70D01091002153136303430323030300C060A2A86240201010101020104203A9723649ADEECE0670A57BE0062C1CFC3C7046232318021866353B4B2837DAB");
    Attribute_t *unsigned_attribute = NULL;

    ASSERT_NOT_NULL(unsigned_attribute = asn_decode_ba_with_alloc(&Attribute_desc, unsigned_attr));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_add_unsigned_attr(NULL, unsigned_attribute));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_add_unsigned_attr(sinfo, NULL));

cleanup:

    ba_free(unsigned_attr);
    ASN_FREE(&Attribute_desc, unsigned_attribute);
}

static void test_sinfo_init(void)
{
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(NULL, 0, &sinfo->sid, &sinfo->digestAlgorithm, sinfo->signedAttrs, &sinfo->signatureAlgorithm, &sinfo->signature, NULL));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(sinfo, 0, NULL, &sinfo->digestAlgorithm, sinfo->signedAttrs, &sinfo->signatureAlgorithm, &sinfo->signature, NULL));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(sinfo, 0, &sinfo->sid, NULL, sinfo->signedAttrs, &sinfo->signatureAlgorithm, &sinfo->signature, NULL));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(sinfo, 0, &sinfo->sid, &sinfo->digestAlgorithm, NULL, &sinfo->signatureAlgorithm, &sinfo->signature, NULL));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(sinfo, 0, &sinfo->sid, &sinfo->digestAlgorithm, sinfo->signedAttrs, NULL, &sinfo->signature, NULL));
    ASSERT_RET(RET_INVALID_PARAM, sinfo_init(sinfo, 0, &sinfo->sid, &sinfo->digestAlgorithm, sinfo->signedAttrs, &sinfo->signatureAlgorithm, NULL, NULL));

cleanup:

    return;
}

void utest_sinfo(void)
{
    PR("%s\n", __FILE__);

    load_test_data();
    if (sinfo) {
        test_sinfo_encode();
        test_sinfo_get_version();
        test_sinfo_get_signer_id();
        test_sinfo_get_signed_attrs();
        test_sinfo_has_signed_attrs();
        test_sinfo_has_unsigned_attrs();
        test_sinfo_get_signed_attr_by_idx();
        test_sinfo_get_signed_attr_by_oid();
        test_sinfo_get_unsigned_attrs();
        test_sinfo_add_unsigned_attr();
        test_sinfo_get_unsigned_attrs_2();
        test_sinfo_get_attrs();
        test_sinfo_verify();
        test_sinfo_verify_signing_cert_v2();
        test_sinfo_get_signed_attrs_2();
        test_sinfo_add_unsigned_attr_2();
        test_sinfo_init();
    }
    sinfo_free(sinfo);
}
