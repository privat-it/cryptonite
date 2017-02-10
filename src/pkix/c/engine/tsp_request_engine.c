/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "tsp_request_engine.h"

#include "log_internal.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "pkix_macros_internal.h"
#include "tsp_request.h"
#include "aid.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/tsp_request_engine.c"

int etspreq_generate_from_hash(AlgorithmIdentifier_t *digest_aid,
        const ByteArray *hash,
        const ByteArray *rnd,
        const OBJECT_IDENTIFIER_t *policy,
        bool cert_req,
        TimeStampReq_t **tsp_req)
{
    int ret = RET_OK;
    MessageImprint_t imprint;
    INTEGER_t *nonce = NULL;
    TimeStampReq_t *time_stamp_req = NULL;

    LOG_ENTRY();

    CHECK_PARAM(digest_aid != NULL);
    CHECK_PARAM(tsp_req != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(policy != NULL);

    memset(&imprint, 0, sizeof(imprint));
    DO(asn_copy(&AlgorithmIdentifier_desc, digest_aid, &imprint.hashAlgorithm));

    DO(asn_ba2OCTSTRING(hash, &imprint.hashedMessage));

    ASN_ALLOC(time_stamp_req);

    DO(asn_long2INTEGER(&time_stamp_req->version, 1));
    DO(tsreq_set_message(time_stamp_req, &imprint));
    DO(tsreq_set_policy(time_stamp_req, policy));
    if (!rnd) {
        DO(tsreq_generate_nonce(time_stamp_req));
    } else {
        DO(asn_create_integer_from_ba(rnd, &nonce));
        DO(tsreq_set_nonce(time_stamp_req, nonce));
    }
    DO(tsreq_set_cert_req(time_stamp_req, cert_req));

    *tsp_req = time_stamp_req;

cleanup:

    ASN_FREE(&INTEGER_desc, nonce);
    ASN_FREE_CONTENT_STATIC(&MessageImprint_desc, &imprint);

    if (RET_OK != ret) {
        ASN_FREE(&TimeStampReq_desc, time_stamp_req);
    }

    return ret;
}

int etspreq_generate(const DigestAdapter *da,
        const ByteArray *msg,
        const ByteArray *rnd,
        OBJECT_IDENTIFIER_t *policy,
        bool cert_req,
        TimeStampReq_t **tsp_req)
{
    int ret = RET_OK;
    DigestAlgorithmIdentifier_t *digest_aid = NULL; /* as AlgorithmIdentifier_t */
    TimeStampReq_t *time_stamp_req = NULL;

    ByteArray *hash = NULL;

    LOG_ENTRY();

    CHECK_PARAM(da != NULL);
    CHECK_PARAM(tsp_req != NULL);
    CHECK_PARAM(msg != NULL);
    CHECK_PARAM(policy != NULL);

    DO(da->get_alg(da, &digest_aid));
    DO(da->update(da, msg));
    DO(da->final(da, &hash));
    DO(etspreq_generate_from_hash(digest_aid, hash, rnd, policy, cert_req, &time_stamp_req));

    *tsp_req = time_stamp_req;

cleanup:

    ASN_FREE(&DigestAlgorithmIdentifier_desc, digest_aid);
    ba_free(hash);

    if (ret != RET_OK) {
        ASN_FREE(&TimeStampReq_desc, time_stamp_req);
    }

    return ret;
}

int etspreq_generate_from_gost34311(const ByteArray *hash,
        const char *policy,
        bool cert_req,
        TimeStampReq_t **tsp_req)
{
    int ret = RET_OK;
    OBJECT_IDENTIFIER_t *policy_oid = NULL;
    AlgorithmIdentifier_t *digest_aid = NULL;

    LOG_ENTRY();

    CHECK_PARAM(tsp_req != NULL);
    CHECK_PARAM(hash != NULL);
    CHECK_PARAM(policy != NULL);

    DO(aid_create_gost3411(&digest_aid));
    DO(asn_create_oid_from_text(policy, &policy_oid));

    DO(etspreq_generate_from_hash(digest_aid, hash, NULL, policy_oid, cert_req, tsp_req));

cleanup:

    ASN_FREE(&OBJECT_IDENTIFIER_desc, policy_oid);
    aid_free(digest_aid);

    return ret;
}
