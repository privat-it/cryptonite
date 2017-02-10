/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "utest.h"

#include "tsp_request_engine.h"
#include "tsp_request.h"
#include "asn1_utils.h"
#include "cryptonite_manager.h"

static void test_etspreq_generate_from_gost34311(void)
{
    ByteArray *hash = ba_alloc_from_le_hex_string("891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    char policy[] = "1.2.804.2.1.1.1.2.2";
    OBJECT_IDENTIFIER_t *exp_policy = NULL;
    OBJECT_IDENTIFIER_t *act_policy = NULL;
    TimeStampReq_t *tsp_req = NULL;
    bool cert_req;

    ASSERT_RET_OK(etspreq_generate_from_gost34311(hash, policy, true, &tsp_req));
    ASSERT_NOT_NULL(tsp_req);

    ASSERT_RET_OK(asn_create_oid_from_text(policy, &exp_policy));
    ASSERT_RET_OK(tsreq_get_policy(tsp_req, &act_policy));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, exp_policy, act_policy);

    ASSERT_RET_OK(tsreq_get_cert_req(tsp_req, &cert_req));
    ASSERT_TRUE(cert_req == true);

cleanup:

    ba_free(hash);
    ASN_FREE(&TimeStampReq_desc, tsp_req);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, exp_policy);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, act_policy);
}

static void test_etspreq_generate(void)
{
    DigestAdapter *da = NULL;
    ByteArray *msg_ba = ba_alloc_from_le_hex_string("0123456789ABCDEF");
    ByteArray *rnd_bytes = ba_alloc_from_le_hex_string("00FF00AA");
    OBJECT_IDENTIFIER_t *policy = NULL;
    OBJECT_IDENTIFIER_t *act_policy = NULL;
    TimeStampReq_t *tsp_req = NULL;
    MessageImprint_t *msg_impr = NULL;
    ByteArray *exp_msg =
            ba_alloc_from_le_hex_string("3030300C060A2A8624020101010102010420867731CC54E37D615934FD6DE9603BD484B04AF86396512CEDD99161539FE753");
    ByteArray *act_msg = NULL;
    INTEGER_t *exp_nonce = NULL;
    INTEGER_t *act_nonce = NULL;
    bool cert_req;

    ASSERT_RET_OK(asn_create_oid_from_text("1.2.804.2.1.1.1.2.2", &policy));
    ASSERT_RET_OK(digest_adapter_init_default(&da));

    ASSERT_RET_OK(etspreq_generate(da, msg_ba, rnd_bytes, policy, false, &tsp_req));
    ASSERT_NOT_NULL(tsp_req);

    ASSERT_RET_OK(tsreq_get_policy(tsp_req, &act_policy));
    ASSERT_EQUALS_ASN(&OBJECT_IDENTIFIER_desc, policy, act_policy);

    ASSERT_RET_OK(tsreq_get_cert_req(tsp_req, &cert_req));
    ASSERT_TRUE(cert_req == false);

    ASSERT_RET_OK(tsreq_get_message(tsp_req, &msg_impr));
    ASSERT_RET_OK(asn_encode_ba(&MessageImprint_desc, msg_impr, &act_msg));
    ASSERT_EQUALS_BA(exp_msg, act_msg);

    ASSERT_RET_OK(asn_create_integer_from_ba(rnd_bytes, &exp_nonce));
    ASSERT_RET_OK(tsreq_get_nonce(tsp_req, &act_nonce));
    ASSERT_EQUALS_ASN(&INTEGER_desc, exp_nonce, act_nonce);

cleanup:

    BA_FREE(msg_ba, rnd_bytes, act_msg, exp_msg);
    digest_adapter_free(da);
    ASN_FREE(&TimeStampReq_desc, tsp_req);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, policy);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, act_policy);
    ASN_FREE(&MessageImprint_desc, msg_impr);
    ASN_FREE(&INTEGER_desc, exp_nonce);
    ASN_FREE(&INTEGER_desc, act_nonce);
}

void utest_tsp_request_engine(void)
{
    PR("%s\n", __FILE__);

    test_etspreq_generate_from_gost34311();
    test_etspreq_generate();
}
