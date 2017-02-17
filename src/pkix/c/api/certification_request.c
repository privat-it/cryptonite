/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "pkix_utils.h"
#include "log_internal.h"
#include "certification_request.h"
#include "pkix_macros_internal.h"
#include "exts.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/certification_request.c"

CertificationRequest_t *creq_alloc(void)
{
    CertificationRequest_t *creq = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(creq);

cleanup:

    return creq;
}

void creq_free(CertificationRequest_t *creq)
{
    LOG_ENTRY();

    if (creq) {
        ASN_FREE(&CertificationRequest_desc, creq);
    }
}

int creq_init_by_sign(CertificationRequest_t *creq,
        const CertificationRequestInfo_t *info,
        const AlgorithmIdentifier_t *aid,
        const BIT_STRING_t *sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(info != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sign != NULL);

    ASN_FREE_CONTENT_PTR(&CertificationRequest_desc, creq);

    DO(asn_copy(&CertificationRequestInfo_desc, info, &creq->certificationRequestInfo));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &creq->signatureAlgorithm));
    DO(asn_copy(&BIT_STRING_desc, sign, &creq->signature));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&CertificationRequest_desc, creq);
    }

    return ret;
}

int creq_init_by_adapter(CertificationRequest_t *creq,
        const CertificationRequestInfo_t *info,
        const SignAdapter *adapter)
{
    int ret = RET_OK;
    ByteArray *sign = NULL;
    ByteArray *info_encoded = NULL;
    ByteArray *alg_ba = NULL;
    AlgorithmIdentifier_t *alg_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(adapter != NULL);
    CHECK_PARAM(info != NULL);

    ASN_FREE_CONTENT_PTR(&CertificationRequest_desc, creq);

    DO(asn_copy(&CertificationRequestInfo_desc, info, &creq->certificationRequestInfo));

    DO(adapter->get_sign_alg(adapter, (AlgorithmIdentifier_t **)&alg_id));
    if (alg_id->parameters != NULL) {
        ASN_FREE(&ANY_desc, alg_id->parameters);
        alg_id->parameters = NULL;
    }

    DO(asn_copy(&AlgorithmIdentifier_desc, alg_id, &creq->signatureAlgorithm));
    DO(asn_encode_ba(&CertificationRequestInfo_desc, info, &info_encoded));
    DO(adapter->sign_data(adapter, info_encoded, &sign));
    DO(sign_ba_to_bs(sign, &creq->signatureAlgorithm, &creq->signature));

cleanup:

    ba_free(alg_ba);
    ba_free(sign);
    ba_free(info_encoded);

    ASN_FREE(&AlgorithmIdentifier_desc, alg_id);
    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&CertificationRequest_desc, creq);
    }

    return ret;
}

int creq_encode(const CertificationRequest_t *creq, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(*out == NULL);

    DO(asn_encode_ba(&CertificationRequest_desc, creq, out));
cleanup:
    return ret;
}

int creq_decode(CertificationRequest_t *creq, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&CertificationRequest_desc, creq);

    DO(asn_decode_ba(&CertificationRequest_desc, creq, in));

cleanup:

    return ret;
}

int creq_get_info(const CertificationRequest_t *creq, CertificationRequestInfo_t **info)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(info != NULL);
    CHECK_PARAM(*info == NULL);

    CHECK_NOT_NULL(*info = asn_copy_with_alloc(&CertificationRequestInfo_desc, &creq->certificationRequestInfo));

cleanup:

    return ret;
}

int creq_get_aid(const CertificationRequest_t *creq, AlgorithmIdentifier_t **aid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(*aid == NULL);

    CHECK_NOT_NULL(*aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &creq->signatureAlgorithm));

cleanup:

    return ret;
}

int creq_get_sign(const CertificationRequest_t *creq, BIT_STRING_t **sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(sign != NULL);
    CHECK_PARAM(*sign == NULL);

    CHECK_NOT_NULL(*sign = asn_copy_with_alloc(&BIT_STRING_desc, &creq->signature));

cleanup:

    return ret;
}

int creq_verify(const CertificationRequest_t *creq, VerifyAdapter *adapter)
{
    int ret = RET_OK;

    ByteArray *buffer = NULL;
    ByteArray *sign = NULL;

    LOG_ENTRY();

    CHECK_PARAM(creq != NULL);
    CHECK_PARAM(adapter != NULL);

    DO(asn_encode_ba(&CertificationRequestInfo_desc, &creq->certificationRequestInfo, &buffer));
    DO(sign_bs_to_ba(&creq->signature, &creq->signatureAlgorithm, &sign));
    DO(adapter->verify_data(adapter, buffer, sign));

cleanup:

    ba_free(sign);
    ba_free(buffer);

    return ret;
}

int creq_get_attributes(const CertificationRequest_t *req, Attributes_t **ext)
{
    int ret = RET_OK;

    CHECK_PARAM(req != NULL);

    CHECK_NOT_NULL(*ext = asn_copy_with_alloc(&Attributes_desc, &req->certificationRequestInfo.attributes));

cleanup:

    return ret;
}

/** Получает указатель на значение искомого расширения. */
static int a_searchfor_sext(const Attributes_t *attrs, const OidNumbers *oid, Extension_t **ext)
{
    int ret = RET_OK;
    int i;
    Extensions_t *exts = NULL;

    LOG_ENTRY();

    CHECK_PARAM(attrs != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(ext != NULL);

    *ext = NULL;

    for (i = 0; i < attrs->list.count; i++) {
        Attribute_t *attr = attrs->list.array[i];

        if (!attr) {
            continue;
        }

        if (pkix_check_oid_equal(&attr->type, oids_get_oid_numbers_by_id(OID_EXTENSION_REQUEST_ID))) {
            if (attr->value.list.count > 0) {
                CHECK_NOT_NULL(exts = asn_any2type(attr->value.list.array[0], &Extensions_desc));
                DO(exts_get_ext_by_oid(exts, oid, ext));
                ASN_FREE(&Extensions_desc, exts);

                return RET_OK;
            }
        }
    }

    SET_ERROR(RET_PKIX_EXT_NOT_FOUND);

cleanup:

    ASN_FREE(&Extensions_desc, exts);

    return ret;
}

int creq_get_ext_by_oid(const CertificationRequest_t *req, const OidNumbers *oid_numbers, Extension_t **ext)
{
    int ret = RET_OK;
    Extension_t *ext_value = NULL;

    LOG_ENTRY();

    CHECK_PARAM(req != NULL);
    CHECK_PARAM(oid_numbers != NULL);
    CHECK_PARAM(ext != 0);

    DO(a_searchfor_sext(&req->certificationRequestInfo.attributes, oid_numbers, &ext_value));

    *ext = ext_value;
    ext_value = NULL;

cleanup:

    ASN_FREE(&Extension_desc, ext_value);

    return ret;
}
