/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"
#include "tsp_request.h"
#include "asn1_utils.h"
#include "pkix_errors.h"

static TimeStampReq_t *load_test_data(void)
{
    ByteArray *decoded = NULL;
    TimeStampReq_t *tsreq = NULL;

    ASSERT_NOT_NULL(tsreq = tsreq_alloc());
    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/tsp_request.dat", &decoded));
    ASSERT_RET_OK(tsreq_decode(tsreq, decoded));

cleanup:
    BA_FREE(decoded);
    return tsreq;
}

static void test_encode(TimeStampReq_t *tsreq)
{
    ByteArray *decoded = NULL;
    ByteArray *encoded = NULL;

    ASSERT_RET_OK(ba_alloc_from_file("src/pkixUtest/resources/tsp_request.dat", &decoded));

    ASSERT_RET_OK(tsreq_encode(tsreq, &encoded));
    ASSERT_NOT_NULL(encoded);

    ASSERT_EQUALS_BA(decoded, encoded);
cleanup:
    BA_FREE(decoded, encoded);
}

static void test_get_message(TimeStampReq_t *tsreq)
{
    MessageImprint_t *msg = NULL;
    ASSERT_RET_OK(tsreq_get_message(tsreq, &msg));
    ASSERT_EQUALS_ASN(&MessageImprint_desc, msg, &tsreq->messageImprint);

cleanup:
    ASN_FREE(&MessageImprint_desc, msg);
}

static void test_set_message(TimeStampReq_t *tsreq)
{
    TimeStampReq_t *tsreq_temp = NULL;

    ASSERT_NOT_NULL(tsreq_temp = tsreq_alloc());
    ASSERT_RET_OK(tsreq_set_message(tsreq_temp, &tsreq->messageImprint));
    ASSERT_EQUALS_ASN(&MessageImprint_desc, &tsreq_temp->messageImprint, &tsreq->messageImprint);

cleanup:

    ASN_FREE(&TimeStampReq_desc, tsreq_temp);
}

static void test_get_policy(TimeStampReq_t *tsreq)
{
    OBJECT_IDENTIFIER_t *policy = NULL;
    ASSERT_RET_OK(tsreq_get_policy(tsreq, &policy));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, policy, tsreq->reqPolicy);

cleanup:
    ASN_FREE(&OBJECT_IDENTIFIER_desc, policy);
}

static void test_set_policy(TimeStampReq_t *tsreq)
{
    TimeStampReq_t *tsreq_temp = NULL;

    ASSERT_NOT_NULL(tsreq_temp = tsreq_alloc());
    ASSERT_RET_OK(tsreq_set_policy(tsreq_temp, tsreq->reqPolicy));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, tsreq_temp->reqPolicy, tsreq->reqPolicy);

cleanup:
    ASN_FREE(&TimeStampReq_desc, tsreq_temp);
}

static void test_set_policy_2(TimeStampReq_t *tsreq)
{
    char policy[] = "1.2.804.2.1.1.1.2.2";
    OBJECT_IDENTIFIER_t *policy_oid = NULL;

    ASSERT_RET_OK(asn_create_oid_from_text(policy, &policy_oid));
    ASSERT_RET_OK(tsreq_set_policy(tsreq, policy_oid));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, tsreq->reqPolicy, policy_oid);

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, policy_oid);
}

static void test_get_nonce(TimeStampReq_t *tsreq)
{
    INTEGER_t *nonce = NULL;
    ASSERT_RET_OK(tsreq_get_nonce(tsreq, &nonce));
    ASSERT_EQUALS_ASN(&INTEGER_desc, nonce, tsreq->nonce);

cleanup:
    ASN_FREE(&INTEGER_desc, nonce);
}

static void test_set_nonce(TimeStampReq_t *tsreq)
{
    TimeStampReq_t *tsreq_temp = NULL;

    ASSERT_NOT_NULL(tsreq_temp = tsreq_alloc());
    ASSERT_RET_OK(tsreq_set_nonce(tsreq_temp, tsreq->nonce));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, tsreq_temp->nonce, tsreq->nonce);

cleanup:
    tsreq_free(tsreq_temp);
}

static void test_get_cert_req(TimeStampReq_t *tsreq)
{
    bool answ;

    ASSERT_RET_OK(tsreq_get_cert_req(tsreq, &answ));
    ASSERT_TRUE(answ);

cleanup:
    return;
}

static void test_set_cert_req(void)
{
    TimeStampReq_t *tsreq = NULL;
    bool answ;

    ASSERT_NOT_NULL(tsreq = tsreq_alloc());

    ASSERT_RET_OK(tsreq_set_cert_req(tsreq, true));
    ASSERT_RET_OK(tsreq_get_cert_req(tsreq, &answ));

    ASSERT_TRUE(answ);

cleanup:
    tsreq_free(tsreq);
}

static void test_get_version(TimeStampReq_t *tsreq)
{
    INTEGER_t *version = NULL;

    ASSERT_RET_OK(tsreq_get_version(tsreq, &version));
    ASSERT_EQUALS_ASN(&INTEGER_desc, &tsreq->version, version);

cleanup:
    ASN_FREE(&INTEGER_desc, version);
}

static void test_get_policy_2(void)
{
    TimeStampReq_t *tsreq = tsreq_alloc();
    OBJECT_IDENTIFIER_t *req_policy = NULL;

    ASSERT_RET(RET_PKIX_TSP_REQ_NO_REQ_POLICY, tsreq_get_policy(tsreq, &req_policy));

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, req_policy);
    tsreq_free(tsreq);
}

static void test_get_nonce_2(void)
{
    TimeStampReq_t *tsreq = tsreq_alloc();
    INTEGER_t *nonce = NULL;

    ASSERT_RET(RET_PKIX_TSP_REQ_NO_NONCE, tsreq_get_nonce(tsreq, &nonce));

cleanup:

    ASN_FREE(&INTEGER_desc, nonce);
    tsreq_free(tsreq);
}

static void test_get_cert_req_2(void)
{
    TimeStampReq_t *tsreq = tsreq_alloc();
    bool answ;

    ASSERT_RET_OK(tsreq_get_cert_req(tsreq, &answ));
    ASSERT_TRUE(answ == false);

cleanup:

    tsreq_free(tsreq);
}

static void test_get_message_2(void)
{
    MessageImprint_t *msg = NULL;
    ASSERT_RET(RET_INVALID_PARAM, tsreq_get_message(NULL, &msg));
    ASSERT_TRUE(msg == NULL);

cleanup:

    ASN_FREE(&MessageImprint_desc, msg);
}

static void test_set_nonce_2(TimeStampReq_t *tsreq)
{
    TimeStampReq_t *tsreq_tmp = NULL;

    ASSERT_NOT_NULL(tsreq_tmp = tsreq_alloc());
    ASSERT_RET(RET_INVALID_PARAM, tsreq_set_nonce(tsreq_tmp, NULL));
    ASSERT_RET(RET_INVALID_PARAM, tsreq_set_nonce(NULL, tsreq->nonce));

cleanup:

    tsreq_free(tsreq_tmp);
}

static void test_tsreq_generate_nonce(void)
{
    ASSERT_RET(RET_INVALID_PARAM, tsreq_generate_nonce(NULL));

cleanup:

    return;
}

static void test_get_version_2(void)
{
    INTEGER_t *version = NULL;

    ASSERT_RET(RET_INVALID_PARAM, tsreq_get_version(NULL, &version));
    ASSERT_TRUE(version == NULL);

cleanup:
    ASN_FREE(&INTEGER_desc, version);
}

void utest_tsp_request(void)
{
    PR("%s\n", __FILE__);

    TimeStampReq_t *tsreq = NULL;

    tsreq = load_test_data();
    if (tsreq) {
        test_encode(tsreq);
        test_get_message(tsreq);
        test_set_message(tsreq);
        test_get_policy(tsreq);
        test_set_policy(tsreq);
        test_set_policy_2(tsreq);
        test_get_nonce(tsreq);
        test_set_nonce(tsreq);
        test_get_cert_req(tsreq);
        test_set_cert_req();
        test_get_version(tsreq);
        test_get_policy_2();
        test_get_nonce_2();
        test_get_cert_req_2();
        test_get_message_2();
        test_set_nonce_2(tsreq);
        test_tsreq_generate_nonce();
        test_get_version_2();
    }

    tsreq_free(tsreq);
}
