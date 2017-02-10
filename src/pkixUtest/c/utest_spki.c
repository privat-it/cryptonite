/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "asn1_utils.h"
#include "spki.h"
#include "aid.h"
#include "pkix_errors.h"

static SubjectPublicKeyInfo_t *load_test_data(void)
{
    ByteArray *spk = ba_alloc_from_le_hex_string(
            "03430004406826CBBDA6FC646B0AA907A542B3389A76B8354219C0EC987BEEDC012D8C382B16ACF9742878FBF4252ABFB16D63D479C630CB2808B58B95CE2AE9079F061C16");
    ByteArray *oid = ba_alloc_from_le_hex_string("060B2A86240201010101030101");
    SubjectPublicKeyInfo_t *spki = NULL;

    ASSERT_NOT_NULL(spki = spki_alloc());
    ASSERT_RET_OK(asn_decode_ba(&BIT_STRING_desc, &spki->subjectPublicKey, spk));
    ASSERT_RET_OK(asn_decode_ba(&OBJECT_IDENTIFIER_desc, &spki->algorithm.algorithm, oid));

cleanup:

    BA_FREE(spk, oid);

    return spki;
}

static void test_encode(SubjectPublicKeyInfo_t *spki)
{
    SubjectPublicKeyInfo_t *spki_temp = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "3054300d060b2a8624020101010103010103430004406826cbbda6fc646b0aa907a542b3389a76b8354219c0ec987beedc012d8c382"
            "b16acf9742878fbf4252abfb16d63d479c630cb2808b58b95ce2ae9079f061c16");
    ASSERT_RET_OK(spki_encode(spki, &actual));
    ASSERT_EQUALS_BA(expected, actual);

    ASSERT_NOT_NULL(spki_temp = spki_alloc());
    ASSERT_RET_OK(spki_decode(spki_temp, actual));

    ASSERT_EQUALS_ASN(&SubjectPublicKeyInfo_desc, spki_temp, spki);

cleanup:

    spki_free(spki_temp);
    BA_FREE(actual, expected);
}

static void test_spki_get_pub_key(SubjectPublicKeyInfo_t *spki)
{
    ByteArray *pub_key = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    SubjectPublicKeyInfo_t *spki_temp = spki_alloc();

    ASSERT_RET_OK(asn_copy(&BIT_STRING_desc, &spki->subjectPublicKey, &spki_temp->subjectPublicKey));
    ASSERT_RET_OK(asn_create_oid_from_text("1.1.1", &oid));
    free(spki->algorithm.algorithm.buf);
    ASSERT_RET_OK(asn_copy(&OBJECT_IDENTIFIER_desc, oid, &spki->algorithm.algorithm));

    ASSERT_RET(RET_PKIX_UNSUPPORTED_SPKI_ALG, spki_get_pub_key(spki, &pub_key));

cleanup:

    ba_free(pub_key);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    spki_free(spki_temp);
}

void utest_spki(void)
{
    SubjectPublicKeyInfo_t *spki = NULL;

    spki = load_test_data();

    if (spki) {
        test_encode(spki);
        test_spki_get_pub_key(spki);
    }

    spki_free(spki);
}
