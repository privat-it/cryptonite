/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "tsp_response.h"
#include "asn1_utils.h"
#include "content_info.h"
#include "pkix_errors.h"
#include "cryptonite_manager.h"
#include "cert.h"

static TimeStampResp_t *test_alloc(void)
{
    ByteArray *decoded = NULL;
    TimeStampResp_t *tsresp = NULL;

    ASSERT_NOT_NULL(tsresp = tsresp_alloc());
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/tsp_response.dat", &decoded));
    ASSERT_RET_OK(tsresp_decode(tsresp, decoded));
cleanup:
    BA_FREE(decoded);
    return tsresp;
}

static void test_encode(TimeStampResp_t *tsresp)
{
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/tsp_response.dat", &decoded));

    ASSERT_RET_OK(tsresp_encode(tsresp, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_EQUALS_BA(decoded, encoded);
cleanup:
    BA_FREE(decoded, encoded);
}

static void test_get_status(TimeStampResp_t *tsresp)
{
    PKIStatusInfo_t *status = NULL;

    ASSERT_RET_OK(tsresp_get_status(tsresp, &status));
    ASSERT_EQUALS_ASN(&PKIStatusInfo_desc, &tsresp->status, status);

cleanup:
    ASN_FREE(&PKIStatusInfo_desc, status);
}

static void test_set_status(TimeStampResp_t *tsresp)
{
    TimeStampResp_t *tsresp_temp = NULL;

    ASSERT_NOT_NULL(tsresp_temp = tsresp_alloc());
    ASSERT_RET_OK(tsresp_set_status(tsresp_temp, &tsresp->status));
    ASSERT_EQUALS_ASN(&PKIStatusInfo_desc, &tsresp->status, &tsresp_temp->status);

cleanup:

    ASN_FREE(&TimeStampResp_desc, tsresp_temp);
}

static void test_get_ts_token(TimeStampResp_t *tsresp)
{
    ContentInfo_t *info = NULL;

    ASSERT_RET_OK(tsresp_get_ts_token(tsresp, &info));
    ASSERT_EQUALS_ASN(&ContentInfo_desc, tsresp->timeStampToken, info);

cleanup:
    cinfo_free(info);
}

static void test_get_ts_token_2(void)
{
    ContentInfo_t *info = NULL;
    TimeStampResp_t *tsresp = tsresp_alloc();

    ASSERT_RET(RET_PKIX_TSP_RESP_NO_TS_TOKEN, tsresp_get_ts_token(tsresp, &info));

cleanup:
    cinfo_free(info);
    tsresp_free(tsresp);
}

static void test_set_ts_token(TimeStampResp_t *tsresp)
{
    TimeStampResp_t *tsresp_temp = NULL;

    ASSERT_NOT_NULL(tsresp_temp = tsresp_alloc());
    ASSERT_RET_OK(tsresp_set_ts_token(tsresp_temp, tsresp->timeStampToken));
    ASSERT_EQUALS_ASN(&ContentInfo_desc, tsresp->timeStampToken, tsresp_temp->timeStampToken);

cleanup:
    tsresp_free(tsresp_temp);
}

static void test_tsresp_verify(void)
{
    TimeStampResp_t *tsresp = tsresp_alloc();
    DigestAdapter *da = NULL;
    VerifyAdapter *va = NULL;
    Certificate_t *cert = cert_alloc();
    ByteArray *buffer = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(digest_adapter_init_by_cert(cert, &da));

    ASSERT_RET(RET_PKIX_TSP_RESP_NO_TS_TOKEN, tsresp_verify(tsresp, da, va));

cleanup:

    ba_free(buffer);
    cert_free(cert);
    verify_adapter_free(va);
    digest_adapter_free(da);
    tsresp_free(tsresp);
}

void utest_tsp_response(void)
{
    PR("%s\n", __FILE__);

    TimeStampResp_t *tsresp = NULL;

    tsresp = test_alloc();
    if (tsresp) {
        test_encode(tsresp);
        test_get_status(tsresp);
        test_set_status(tsresp);
        test_get_ts_token(tsresp);
        test_get_ts_token_2();
        test_set_ts_token(tsresp);
        test_tsresp_verify();
    }

    tsresp_free(tsresp);
}
