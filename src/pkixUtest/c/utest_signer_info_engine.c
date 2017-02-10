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
#include "signer_info.h"

static void test_esigner_info_generate(void)
{
    DigestAdapter *da = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    SignerInfoEngine *signer_info_engine = NULL;
    SignerInfo_t *sinfo = NULL;
    Attributes_t *signed_attributes = NULL;
    Attributes_t *unsigned_attributes = NULL;
    Attribute_t *unsigned_attribute = NULL;
    Attribute_t *attr = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    int format;

    ByteArray *hash = ba_alloc_from_le_hex_string("1C224E69E40733FE4BC0CAFB31F8FB980EEAF25E83B7A0031D45BBE8BC2FF89E");
    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;
    ByteArray *signed_attrs = NULL;
    ByteArray *unsigned_attrs = NULL;
    ByteArray *unsigned_attr =
            ba_alloc_from_le_hex_string("3045060B2A864886F70D01091002153136303430323030300C060A2A86240201010101020104203A9723649ADEECE0670A57BE0062C1CFC3C7046232318021866353B4B2837DAB");

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userur_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));
    ASSERT_RET_OK(esigner_info_alloc(sa, da, NULL, &signer_info_engine));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_signed_attr.der", &signed_attrs));
    ASSERT_NOT_NULL(signed_attributes = asn_decode_ba_with_alloc(&Attributes_desc, signed_attrs));
    ASSERT_RET_OK(esigner_info_set_signed_attrs(signer_info_engine, signed_attributes));

    ASSERT_NOT_NULL(unsigned_attribute = asn_decode_ba_with_alloc(&Attribute_desc, unsigned_attr));
    ASSERT_RET_OK(esigner_info_add_unsigned_attr(signer_info_engine, unsigned_attribute));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/test_cms_unsigned_attr.der", &unsigned_attrs));
    ASSERT_NOT_NULL(unsigned_attributes = asn_decode_ba_with_alloc(&Attributes_desc, unsigned_attrs));
    ASSERT_RET_OK(esigner_info_set_unsigned_attrs(signer_info_engine, unsigned_attributes));

    ASSERT_RET_OK(esigner_info_set_bes_attrs(signer_info_engine, false));

    ASSERT_RET_OK(esigner_info_generate(signer_info_engine, &sinfo));
    ASSERT_NOT_NULL(sinfo);

    ASSERT_RET_OK(sinfo_get_format(sinfo, &format));
    ASSERT_TRUE(format & 0x1);
    ASSERT_TRUE(!(format & 0x2));
    ASSERT_TRUE(format & 0x4);
    ASSERT_TRUE(!(format & 0x8));

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(sinfo_verify_without_data(sinfo, da, va));

    ASSERT_RET_OK(sinfo_get_unsigned_attr_by_idx(sinfo, 0, &attr));
    ASSERT_EQUALS_ASN(&Attribute_desc, unsigned_attribute, attr);
    ASN_FREE(&Attribute_desc, attr);
    attr = NULL;

    ASSERT_RET_OK(asn_create_oid_from_text("1.2.840.113549.1.9.16.2.21", &oid));
    ASSERT_RET_OK(sinfo_get_unsigned_attr_by_oid(sinfo, oid, &attr));
    ASSERT_EQUALS_ASN(&Attribute_desc, unsigned_attribute, attr);
    ASN_FREE(&Attribute_desc, attr);
    attr = NULL;

    ASSERT_RET_OK(sinfo_get_message_digest(sinfo, &buffer));
    ASSERT_EQUALS_BA(hash, buffer);
    ba_free(buffer);
    buffer = NULL;

cleanup:

    BA_FREE(private_key, unsigned_attr, signed_attrs, unsigned_attrs, hash);
    digest_adapter_free(da);
    sign_adapter_free(sa);
    verify_adapter_free(va);
    cert_free(cert);
    ASN_FREE(&Attributes_desc, signed_attributes);
    ASN_FREE(&Attributes_desc, unsigned_attributes);
    ASN_FREE(&Attribute_desc, unsigned_attribute);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    esigner_info_free(signer_info_engine);
    sinfo_free(sinfo);
}

void utest_signer_info_engine(void)
{
    PR("%s\n", __FILE__);

    test_esigner_info_generate();
}

