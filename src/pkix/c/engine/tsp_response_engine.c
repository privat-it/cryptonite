/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "tsp_response_engine.h"
#include "log_internal.h"
#include "oids.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "pkix_macros_internal.h"
#include "cryptonite_manager.h"
#include "tsp_request.h"
#include "content_info.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/tsp_response_engine.c"

static bool with_mods;

static AdaptersMap *get_signer(const OidNumbers *oid_arr, const AdaptersMap *tsp_map_gl)
{
    AdaptersMap *single_adapter = NULL;
    int i;
    AlgorithmIdentifier_t *alg_oid = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    if (!oid_arr || !tsp_map_gl) {
        return NULL ;
    }

    for (i = 0; i < tsp_map_gl->count; i++) {
        alg_oid = NULL;
        tsp_map_gl->sign[i]->get_sign_alg(tsp_map_gl->sign[i], &alg_oid);

        if (asn_check_oid_parent(&alg_oid->algorithm, oid_arr->numbers, oid_arr->numbers_len)) {
            CHECK_NOT_NULL(single_adapter = adapters_map_alloc());

            adapters_map_add(single_adapter, tsp_map_gl->digest[i], tsp_map_gl->sign[i]);

            ASN_FREE(&AlgorithmIdentifier_desc, alg_oid);

            return single_adapter;
        }

        ASN_FREE(&AlgorithmIdentifier_desc, alg_oid);
        alg_oid = NULL;
    }

cleanup:

    ASN_FREE(&AlgorithmIdentifier_desc, alg_oid);

    return NULL;
}

static AdaptersMap *prepare_signer(const TimeStampReq_t *req, const AdaptersMap *tsp_map_gl)
{
    LOG_ENTRY();
    /** Флаг формирования ответа с модификациями. */
    with_mods = false;

    if (!tsp_map_gl || !req) {
        return NULL ;
    }

    if (!req->reqPolicy) {
        with_mods = true;
        return get_signer(oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_LE_ID), tsp_map_gl);

    } else if (pkix_check_oid_equal(req->reqPolicy, oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_PB_ID))) {
        return get_signer(oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_LE_ID), tsp_map_gl);

    } else if (pkix_check_oid_equal(req->reqPolicy, oids_get_oid_numbers_by_id(OID_PKI_TSP_POLICY_DSTU_ONB_ID))) {
        return get_signer(oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_ONB_LE_ID), tsp_map_gl);

    } else {
        return NULL;
    }
}

static int validate_aid(const MessageImprint_t *mess_impr, const DigestAlgorithmIdentifiers_t *tsp_digest_aids)
{
    int ret = RET_OK;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(mess_impr != NULL);
    CHECK_PARAM(tsp_digest_aids != NULL);

    for (i = 0; i < tsp_digest_aids->list.count; i++) {
        if (asn_equals(&AlgorithmIdentifier_desc, tsp_digest_aids->list.array[i], &mess_impr->hashAlgorithm)) {
            return RET_OK;
        }
    }

    SET_ERROR(RET_PKIX_DIFFERENT_DIGEST_ALG);

cleanup:

    return ret;
}

static int try_generate(ContentInfo_t **content_info,
        const time_t *current_time_gl,
        const DigestAlgorithmIdentifiers_t *tsp_digest_aids,
        const INTEGER_t *sn_gl,
        const AdaptersMap *tsp_map_gl,
        const ByteArray *tsp_req_gl)
{
    int ret = RET_OK;

    AdaptersMap *entry = NULL;
    TSTInfo_t *info = NULL;
    TimeStampReq_t *req = NULL;
    GeneralizedTime_t *gen_time = NULL;

    Certificate_t *cert = NULL;
    Name_t *tsa_authority = NULL;
    GeneralName_t *general_name = NULL;
    Certificate_t *cert_for_sd = NULL;
    SignedData_t *signed_data = NULL;

    SignedDataEngine *sd_engine = NULL;
    SignerInfoEngine *si_engine = NULL;
    ContentInfo_t *content = NULL;

    bool flag;
    ByteArray *encoded = NULL;

    LOG_ENTRY();

    CHECK_PARAM(current_time_gl != NULL);
    CHECK_PARAM(tsp_digest_aids != NULL);
    CHECK_PARAM(sn_gl != NULL);
    CHECK_PARAM(tsp_map_gl != NULL);
    CHECK_PARAM(tsp_req_gl != NULL);

    CHECK_NOT_NULL(req = tsreq_alloc());
    DO(tsreq_decode(req, tsp_req_gl));

    DO(validate_aid(&req->messageImprint, tsp_digest_aids));

    entry = prepare_signer(req, tsp_map_gl);
    if (!entry || entry->count != 1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    ASN_ALLOC(info);

    DO(asn_copy(&TSAPolicyId_desc, req->reqPolicy, &info->policy));
    DO(asn_copy(&MessageImprint_desc, &req->messageImprint, &info->messageImprint));
    DO(asn_copy(&INTEGER_desc, sn_gl, &info->serialNumber));

    DO(asn_long2INTEGER(&info->version, 1));

    CHECK_NOT_NULL(gen_time = asn_time2GT(NULL, localtime(current_time_gl), true));

    DO(asn_copy(&GeneralizedTime_desc, gen_time, &info->genTime));
    CHECK_NOT_NULL(info->nonce = asn_copy_with_alloc(&INTEGER_desc, req->nonce));

    DO(entry->sign[0]->has_cert(entry->sign[0], &flag));

    if (flag) {
        DO(entry->sign[0]->get_cert(entry->sign[0], &cert));
        CHECK_NOT_NULL(tsa_authority = asn_copy_with_alloc(&Name_desc, &cert->tbsCertificate.subject));

        ASN_ALLOC(general_name);
        general_name->present = GeneralName_PR_directoryName;
        DO(asn_copy(&Name_desc, tsa_authority, &general_name->choice.directoryName));
        CHECK_NOT_NULL(info->tsa = asn_copy_with_alloc(&GeneralName_desc, general_name));
    }

    DO(asn_encode_ba(&TSTInfo_desc, info, &encoded));

    /* Формируем контейнер подписи. */
    DO(esigner_info_alloc(entry->sign[0], entry->digest[0], NULL, &si_engine));
    DO(esigned_data_alloc(si_engine, &sd_engine));
    DO(esigned_data_set_data(sd_engine, oids_get_oid_numbers_by_id(OID_CT_TST_INFO_ID), encoded, true));

    if (req->certReq) {
        entry->sign[0]->get_cert(entry->sign[0], &cert_for_sd);
        DO(esigned_data_add_cert(sd_engine, cert_for_sd));
    }

    DO(esigned_data_generate(sd_engine, &signed_data));

    CHECK_NOT_NULL(content = cinfo_alloc());
    DO(cinfo_init_by_signed_data(content, signed_data));

    *content_info = content;

cleanup:

    ASN_FREE(&TSTInfo_desc, info);
    ASN_FREE(&TimeStampReq_desc, req);
    ASN_FREE(&GeneralizedTime_desc, gen_time);
    ASN_FREE(&Certificate_desc, cert);
    ASN_FREE(&Name_desc, tsa_authority);
    ASN_FREE(&GeneralName_desc, general_name);
    ASN_FREE(&Certificate_desc, cert_for_sd);
    ASN_FREE(&SignedData_desc, signed_data);
    esigned_data_free(sd_engine);
    ba_free(encoded);
    adapters_map_with_const_content_free(entry);

    if (ret != RET_OK) {
        ASN_FREE(&ContentInfo_desc, content);
    }

    return ret;
}

int etspresp_generate(const AdaptersMap *tsp_map,
        const ByteArray *tsp_req,
        const INTEGER_t *sn,
        const DigestAlgorithmIdentifiers_t *tsp_digest_aids,
        const time_t *current_time,
        TimeStampResp_t **tsp_resp)
{
    int ret = RET_OK;
    ContentInfo_t *info = NULL;
    PKIStatus_t *status = NULL;
    PKIStatusInfo_t *pkx_st_info = NULL;
    TimeStampResp_t *time_stamp_resp = NULL;

    LOG_ENTRY();

    CHECK_PARAM(tsp_map != NULL);
    CHECK_PARAM(tsp_req != NULL);
    CHECK_PARAM(sn != NULL);
    CHECK_PARAM(tsp_digest_aids != NULL);
    CHECK_PARAM(current_time != NULL);

    DO(try_generate(&info, current_time, tsp_digest_aids, sn, tsp_map, tsp_req));

    DO(asn_create_integer_from_long((with_mods) ? PKIStatus_grantedWithMods : PKIStatus_granted, &status));

    ASN_ALLOC(pkx_st_info);
    DO(asn_copy(&PKIStatus_desc, status, &pkx_st_info->status));

    ASN_ALLOC(time_stamp_resp);
    DO(asn_copy(&PKIStatusInfo_desc, pkx_st_info,  &time_stamp_resp->status));
    CHECK_NOT_NULL(time_stamp_resp->timeStampToken = asn_copy_with_alloc(&ContentInfo_desc, info));

    *tsp_resp = time_stamp_resp;

cleanup:

    ASN_FREE(&PKIStatus_desc, status);
    ASN_FREE(&PKIStatusInfo_desc, pkx_st_info);
    ASN_FREE(&ContentInfo_desc, info);

    if (ret != RET_OK) {
        ASN_FREE(&TimeStampResp_desc, time_stamp_resp);
    }

    return ret;
}
