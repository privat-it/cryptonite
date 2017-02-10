/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "tsp_response_engine.h"
#include "tsp_response.h"
#include "asn1_utils.h"
#include "cryptonite_manager.h"
#include "adapters_map.h"
#include "cert.h"
#include "aid.h"

static void test_etspresp_generate(void)
{
    TimeStampResp_t *tsp_response = NULL;
    DigestAdapter *da = NULL;
    SignAdapter *sa = NULL;
    VerifyAdapter *va = NULL;
    AdaptersMap *tsp_map = adapters_map_alloc();

    Certificate_t *cert = cert_alloc();

    ByteArray *buffer = NULL;
    ByteArray *private_key = NULL;
    ByteArray *tsp_req = NULL;

    AlgorithmIdentifier_t *hash_alg = NULL;
    DigestAlgorithmIdentifiers_t *tsp_digest_algs = NULL;
    INTEGER_t *sn = NULL;

    time_t current_time;
    time(&current_time);

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_private_key_ba.dat",
            &private_key));
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/userfiz_certificate.cer",
            &buffer));
    ASSERT_RET_OK(cert_decode(cert, buffer));
    ba_free(buffer);
    buffer = NULL;

    ASSERT_RET_OK(digest_adapter_init_default(&da));
    ASSERT_RET_OK(sign_adapter_init_by_cert(private_key, cert, &sa));
    ASSERT_RET_OK(adapters_map_add(tsp_map, da, sa));

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/pkiExample_DSTU4145_M257_PB/tsp_request.der", &tsp_req));

    ASSERT_RET_OK(aid_create_gost3411(&hash_alg));
    ASSERT_ASN_ALLOC(tsp_digest_algs);
    ASN_SET_ADD(tsp_digest_algs, hash_alg);

    ASSERT_RET_OK(asn_create_integer_from_long(128, &sn));

    ASSERT_RET_OK(etspresp_generate(tsp_map, tsp_req, sn, tsp_digest_algs, &current_time, &tsp_response));
    ASSERT_NOT_NULL(tsp_response);

    ASSERT_RET_OK(verify_adapter_init_by_cert(cert, &va));
    ASSERT_RET_OK(tsresp_verify(tsp_response, da, va));

cleanup:

    BA_FREE(private_key, tsp_req);
    adapters_map_free(tsp_map);
    verify_adapter_free(va);
    cert_free(cert);
    ASN_FREE(&DigestAlgorithmIdentifiers_desc, tsp_digest_algs);
    ASN_FREE(&TimeStampResp_desc, tsp_response);
    ASN_FREE(&INTEGER_desc, sn);
}

void utest_tsp_response_engine(void)
{
    PR("%s\n", __FILE__);

    test_etspresp_generate();
}
