/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "cert.h"
#include "ocsp_response.h"
#include "asn1_utils.h"
#include "pkix_errors.h"
#include "cryptonite_manager.h"

static OCSPResponse_t *test_alloc(void)
{
    OCSPResponse_t *ocspr = NULL;

    ASSERT_NOT_NULL(ocspr = ocspresp_alloc());
cleanup:
    return ocspr;
}

static void test_decode(OCSPResponse_t *ocspr)
{
    ByteArray *decoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp_response.dat", &decoded));
    ASSERT_RET_OK(ocspresp_decode(ocspr, decoded));

cleanup:
    BA_FREE(decoded);
}

static void test_encode(OCSPResponse_t *ocspr)
{
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp_response.dat", &decoded));

    ASSERT_RET_OK(ocspresp_encode(ocspr, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_EQUALS_BA(decoded, encoded);
cleanup:
    BA_FREE(decoded, encoded);
}

static void test_get_ts_token(OCSPResponse_t *ocspr)
{
    OCSPResponseStatus_t *status = NULL;

    ASSERT_RET_OK(ocspresp_get_status(ocspr, &status));
    ASSERT_NOT_NULL(status);

    ASSERT_EQUALS_ASN(&OCSPResponseStatus_desc, &ocspr->responseStatus, status);

cleanup:
    ASN_FREE(&OCSPResponseStatus_desc, status);
}

static void test_set_ts_token(OCSPResponse_t *ocspr)
{
    OCSPResponse_t *ocspr_temp = NULL;

    ASSERT_NOT_NULL(ocspr_temp = ocspresp_alloc());
    ASSERT_RET_OK(ocspresp_set_status(ocspr_temp, &ocspr->responseStatus));
    ASSERT_EQUALS_ASN(&OCSPResponseStatus_desc, &ocspr->responseStatus, &ocspr_temp->responseStatus);

cleanup:

    ocspresp_free(ocspr_temp);
}

static void test_get_response_bytes(OCSPResponse_t *ocspr)
{
    ResponseBytes_t *bytes = NULL;

    ASSERT_RET_OK(ocspresp_get_response_bytes(ocspr, &bytes));
    ASSERT_NOT_NULL(bytes);

    ASSERT_EQUALS_ASN(&ResponseBytes_desc, ocspr->responseBytes, bytes);

cleanup:
    ASN_FREE(&ResponseBytes_desc, bytes);
}

static void test_get_response_bytes_2(void)
{
    OCSPResponse_t *ocspr = ocspresp_alloc();
    ResponseBytes_t *bytes = NULL;

    ASSERT_RET(RET_PKIX_OCSP_RESP_NO_BYTES, ocspresp_get_response_bytes(ocspr, &bytes));
    ASSERT_TRUE(bytes == NULL);

cleanup:

    ocspresp_free(ocspr);
}

static void test_set_response_bytes(OCSPResponse_t *ocspr)
{
    OCSPResponse_t *ocspr_temp = NULL;

    ASSERT_NOT_NULL(ocspr_temp = ocspresp_alloc());
    ASSERT_RET_OK(ocspresp_set_response_bytes(ocspr_temp, ocspr->responseBytes));
    ASSERT_EQUALS_ASN(&ResponseBytes_desc, ocspr->responseBytes, ocspr_temp->responseBytes);

cleanup:
    ocspresp_free(ocspr_temp);
}

static void test_get_certs(OCSPResponse_t *ocspr)
{
    Certificate_t **certs = NULL;
    int cert_len, i;
    ByteArray *exp_cert =
            ba_alloc_from_le_hex_string("308202C2308201ACA003020102020101300B06092A864886F70D010105301E311C3009060355040613025255300F06035504031E080054006500730074301E170D3133303133313232303030305A170D3136303133313232303030305A301E311C3009060355040613025255300F06035504031E08005400650073007430820122300D06092A864886F70D01010105000382010F003082010A0282010100D8BE412580D1815E06B8187D2C95A9DE942BA00581F4160279A63E01155435E86BFD3B836C3191490BDC6359800FF19BD284025C32FE26EBEB36DF9350598A2808CCA882B393E29441F7576C4466D7CBF9779D394A704DA4C240177A06129B0873912E3D307D56D39AA33E8B156E6E630EBDCBBA9B3AB4F74604C56533E1160D00A4E24DD025FF776AF46D8AD1904885542B0FD261DE29684B41C02BC48E0FC24AC52D1D904453986385931CBB387A4BC8995FBE26F6C2FA7FE98618C73DC61719B9317F33DF6BFF0C585C3FB43197BEB94CCC6EC63000B4290D99763E09ABE27D065573072A573CC6FEEA4CFD21B049F3DA361B6908D03CF0822A9F2E9232A30203010001A30F300D300B0603551D0F040403020002300B06092A864886F70D0101050382010100692413263CEB1317E1B0F29BD790ABC38ECFA947FD529E3465754189AB1BB940BE85E2F854382BAA9C822A66D1808A8B103AB4C0560CEDC1734D6BDD64092027366EB633D883093935768A84893276C2C281255C0F750041EE19C821863AFBD80C2ABE3AE72DFBA367D5BC2409901834FD7967F9AA47F54FE2F95FB6CE9D65373E980AEFFF80C4B687AE89C3505F760E7E191F42765C844B0996AE405A6AF34FBD9418FBA12BE006F5689844590C2695B6702D59CBD365CBB4CA8070612C2347197B94E2D1A5420F743986D9A88D9340B45E49B65149ADD5C7A7EB61C7FBA019A5F373FDE6A61A0C884BA56E2539244419636ED6814731133DACBF034F051CF4");
    ByteArray *act_cert = NULL;

    ASSERT_RET_OK(ocspresp_get_certs(ocspr, &certs, &cert_len));
    ASSERT_NOT_NULL(certs);
    ASSERT_TRUE(cert_len == 1);

    ASSERT_RET_OK(cert_encode(certs[0], &act_cert));
    ASSERT_EQUALS_BA(exp_cert, act_cert);

cleanup:

    BA_FREE(exp_cert, act_cert);

    for (i = 0; i < cert_len; ++i) {
        cert_free(certs[i]);
    }

    free(certs);
}

static void test_get_certs_2(void)
{
    OCSPResponse_t *ocspr = ocspresp_alloc();
    Certificate_t **certs = NULL;
    int cert_len;

    ASSERT_RET(RET_PKIX_OCSP_RESP_NO_BYTES, ocspresp_get_certs(ocspr, &certs, &cert_len));
    ASSERT_TRUE(certs == NULL);

cleanup:

    ocspresp_free(ocspr);
}

static void test_get_certs_status(OCSPResponse_t *ocspr)
{
    OcspCertStatus **status = NULL;
    int status_len, i;

    ASSERT_RET_OK(ocspresp_get_certs_status(ocspr, &status, &status_len));
    ASSERT_NOT_NULL(status);
    ASSERT_TRUE(status_len == 1);

    ASSERT_TRUE(strcmp(status[0]->status, "good") == 0);

cleanup:

    for (i = 0; i < status_len; ++i) {
        ocspresp_certs_status_free(status[i]);
    }

    free(status);
}

static void test_get_certs_status_2(void)
{
    OcspCertStatus **status = NULL;
    int status_len;
    ByteArray *decoded = ba_alloc_from_le_hex_string("30030A0101");
    OCSPResponse_t *ocsp_resp = ocspresp_alloc();

    ASSERT_RET_OK(ocspresp_decode(ocsp_resp, decoded));

    ASSERT_RET(RET_PKIX_OCSP_RESP_NO_BYTES, ocspresp_get_certs_status(ocsp_resp, &status, &status_len));
    ASSERT_TRUE(status == NULL);

cleanup:

    free(status);

    ba_free(decoded);
    ocspresp_free(ocsp_resp);
}

static void test_get_certs_status_3(void)
{
    OcspCertStatus **status = NULL;
    int status_len = 0;
    int i;
    ByteArray *decoded = NULL;
    OCSPResponse_t *ocsp_resp = ocspresp_alloc();

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/ocsp_resp_for_revoked_cert.dat", &decoded));
    ASSERT_RET_OK(ocspresp_decode(ocsp_resp, decoded));

    ASSERT_RET_OK(ocspresp_get_certs_status(ocsp_resp, &status, &status_len));
    ASSERT_NOT_NULL(status);
    ASSERT_TRUE(status_len == 1);

    ASSERT_TRUE(strcmp(status[0]->status, "revoked") == 0);
    ASSERT_TRUE(strcmp(status[0]->revocationReason, "affiliationChanged") == 0);

cleanup:

    for (i = 0; i < status_len; ++i) {
        ocspresp_certs_status_free(status[i]);
    }

    free(status);

    ba_free(decoded);
    ocspresp_free(ocsp_resp);
}

static void test_get_responder_ids(OCSPResponse_t *ocspr)
{
    ResponderID_t *status = NULL;
    ByteArray *actual = NULL;
    ByteArray *expected =
            ba_alloc_from_le_hex_string("a120301e311c3009060355040613025255300f06035504031e080054006500730074");

    ASSERT_RET_OK(ocspresp_get_responder_id(ocspr, &status));
    ASSERT_RET_OK(asn_encode_ba(&ResponderID_desc, status, &actual));

    ASSERT_EQUALS_BA(expected, actual);

cleanup:

    ASN_FREE(&ResponderID_desc, status);
    BA_FREE(expected, actual);
}

static void test_get_responder_id_2(void)
{
    OCSPResponse_t *ocspr = ocspresp_alloc();
    ResponderID_t *resp_id = NULL;

    ASSERT_RET(RET_PKIX_OCSP_RESP_NO_BYTES, ocspresp_get_responder_id(ocspr, &resp_id));
    ASSERT_TRUE(resp_id == NULL);

cleanup:

    ocspresp_free(ocspr);
    ASN_FREE(&ResponderID_desc, resp_id);
}

static void test_ocspresp_verify(void)
{
    OCSPResponse_t *ocspr = ocspresp_alloc();
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));

    ASSERT_RET(RET_PKIX_OCSP_RESP_NO_BYTES, ocspresp_verify(ocspr, va));

cleanup:

    ocspresp_free(ocspr);
    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
}

static void test_set_response_bytes_2(OCSPResponse_t *ocspr)
{
    ASSERT_RET(RET_INVALID_PARAM, ocspresp_set_response_bytes(NULL, ocspr->responseBytes));
    ASSERT_RET(RET_INVALID_PARAM, ocspresp_set_response_bytes(ocspr, NULL));

cleanup:

    return;
}

void utest_ocsp_response(void)
{
    PR("%s\n", __FILE__);

    OCSPResponse_t *ocspr = NULL;

    ocspr = test_alloc();

    if (ocspr) {
        test_decode(ocspr);
        test_encode(ocspr);
        test_get_ts_token(ocspr);
        test_set_ts_token(ocspr);
        test_get_response_bytes(ocspr);
        test_get_response_bytes_2();
        test_set_response_bytes(ocspr);
        test_get_certs(ocspr);
        test_get_certs_2();
        test_get_certs_status(ocspr);
        test_get_certs_status_2();
        test_get_certs_status_3();
        test_get_responder_ids(ocspr);
        test_get_responder_id_2();
        test_ocspresp_verify();
        test_set_response_bytes_2(ocspr);
    }

    ocspresp_free(ocspr);

}
