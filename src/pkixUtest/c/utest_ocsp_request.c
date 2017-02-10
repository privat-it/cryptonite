/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "ocsp_request.h"
#include "asn1_utils.h"
#include "ocsp_request_engine.h"
#include "cert.h"
#include "cryptonite_manager.h"
#include "pkix_errors.h"

static OCSPRequest_t *ocspreq = NULL;

static void load_test_data(void)
{
    ByteArray *encoded = NULL;
    ByteArray *decoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp_request.dat", &decoded));
    ASSERT_NOT_NULL(decoded);
    ASSERT_NOT_NULL(ocspreq = ocspreq_alloc());
    ASSERT_RET_OK(ocspreq_decode(ocspreq, decoded));

cleanup:
    BA_FREE(encoded, decoded);
}

static void test_encode(void)
{
    ByteArray *decoded = NULL;
    ByteArray *actual = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp_request.dat", &decoded));
    ASSERT_RET_OK(ocspreq_encode(ocspreq, &actual));
    ASSERT_EQUALS_BA(decoded, actual);

cleanup:
    BA_FREE(decoded, actual);
}

static void test_ocspreq_get_tbsreq(void)
{
    TBSRequest_t *tbsreq = NULL;
    ByteArray *tbsreq_ba = NULL;
    ByteArray *expected = ba_alloc_from_le_hex_string(
            "308195306C306A3068300C060A2A8624020101010102010420305A35E24820678A3F6879A95734C98C654C31200315DD0D8"
            "D341EDC928CE28704208D84EDA1BB9381E8C31190A8AC92853FC4D8C784C64A01B8371157D85D18555702140D84EDA1BB93"
            "81E804000000209E0200D68B0700A2253023302106092B0601050507300102041494E533F8225EC8421B46828880C7A8D32"
            "79F8061");

    ASSERT_NOT_NULL(expected);
    ASSERT_RET_OK(ocspreq_get_tbsreq(ocspreq, &tbsreq));
    ASSERT_RET_OK(asn_encode_ba(&TBSRequest_desc, tbsreq, &tbsreq_ba));

    ASSERT_EQUALS_BA(expected, tbsreq_ba);

cleanup:
    BA_FREE(expected, tbsreq_ba);
    ASN_FREE(&TBSRequest_desc, tbsreq);
}

static void test_ocspreq_set_tbsreq(void)
{
    OCSPRequest_t *ocspreq_temp = NULL;

    ASSERT_NOT_NULL(ocspreq_temp = ocspreq_alloc());
    ASSERT_RET_OK(ocspreq_set_tbsreq(ocspreq_temp, &ocspreq->tbsRequest));

    ASSERT_EQUALS_ASN(&TBSRequest_desc, &ocspreq->tbsRequest, &ocspreq_temp->tbsRequest);
cleanup:
    ocspreq_free(ocspreq_temp);
}

static void test_ocspreq_get_sign(void)
{
    Signature_t *sign = NULL;

    ASSERT_RET_OK(ocspreq_get_sign(ocspreq, &sign));
    ASSERT_TRUE(sign == NULL);

cleanup:
    ASN_FREE(&Signature_desc, sign);
}

static void test_ocspreq_has_sign(void)
{
    bool answ;

    ASSERT_RET_OK(ocspreq_has_sign(ocspreq, &answ));
    ASSERT_TRUE(answ == false);

cleanup:
    return;
}

static void test_ocspreq_set_sign(void)
{
    OCSPRequest_t *ocspreq = NULL;
    OCSPRequest_t *ocspreq_temp = NULL;
    ByteArray *ocspreq_ba = NULL;
    Signature_t *sign = NULL;

    ASSERT_NOT_NULL(ocspreq_temp = ocspreq_alloc());

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/oscp_request_with_sign.dat", &ocspreq_ba));
    ASSERT_NOT_NULL(ocspreq = asn_decode_ba_with_alloc(&OCSPRequest_desc, ocspreq_ba));

    ASSERT_RET_OK(ocspreq_set_sign(ocspreq_temp, ocspreq->optionalSignature));
    ASSERT_RET_OK(ocspreq_get_sign(ocspreq_temp, &sign));
    ASSERT_EQUALS_ASN(&Signature_desc, ocspreq->optionalSignature, sign);

cleanup:

    ba_free(ocspreq_ba);
    ocspreq_free(ocspreq_temp);
    ocspreq_free(ocspreq);
    ASN_FREE(&Signature_desc, sign);
}

static void test_ocspreq_verify(void)
{
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    OCSPRequest_t *ocspreq = ocspreq_alloc();
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET(RET_PKIX_OCSP_REQ_NO_SIGN, ocspreq_verify(ocspreq, va));

cleanup:

    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
    ocspreq_free(ocspreq);
}

static void test_ocspreq_get_tbsreq_2(void)
{
    TBSRequest_t *tbsreq = NULL;

    ASSERT_RET(RET_INVALID_PARAM, ocspreq_get_tbsreq(NULL, &tbsreq));
    ASSERT_TRUE(tbsreq == NULL);

cleanup:

    ASN_FREE(&TBSRequest_desc, tbsreq);
}

static void test_ocspreq_set_sign_2(void)
{
    OCSPRequest_t *ocspreq = NULL;
    ByteArray *ocspreq_ba = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/oscp_request_with_sign.dat", &ocspreq_ba));
    ASSERT_NOT_NULL(ocspreq = asn_decode_ba_with_alloc(&OCSPRequest_desc, ocspreq_ba));

    ASSERT_RET(RET_INVALID_PARAM, ocspreq_set_sign(NULL, ocspreq->optionalSignature));
    ASSERT_RET(RET_INVALID_PARAM, ocspreq_set_sign(ocspreq, NULL));

cleanup:

    ba_free(ocspreq_ba);
    ocspreq_free(ocspreq);
}

void utest_ocsp_request(void)
{
    PR("%s\n", __FILE__);

    load_test_data();
    if (ocspreq) {
        test_encode();
        test_ocspreq_get_tbsreq();
        test_ocspreq_set_tbsreq();
        test_ocspreq_get_sign();
        test_ocspreq_has_sign();
        test_ocspreq_set_sign();
        test_ocspreq_verify();
        test_ocspreq_get_tbsreq_2();
        test_ocspreq_set_sign_2();
    }

    ocspreq_free(ocspreq);
}
