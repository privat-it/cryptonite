/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "log_internal.h"
#include "pkix_utils.h"
#include "ocsp_request.h"

#include "cert.h"
#include "pkix_macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/ocsp_request.c"

OCSPRequest_t *ocspreq_alloc(void)
{
    OCSPRequest_t *ocspreq = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(ocspreq);

cleanup:

    return ocspreq;
}

void ocspreq_free(OCSPRequest_t *ocspreq)
{
    LOG_ENTRY();

    if (ocspreq) {
        ASN_FREE(&OCSPRequest_desc, ocspreq);
    }
}

int ocspreq_encode(const OCSPRequest_t *ocspreq, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&OCSPRequest_desc, ocspreq, out));
cleanup:
    return ret;
}

int ocspreq_decode(OCSPRequest_t *ocspreq, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&OCSPRequest_desc, ocspreq);

    DO(asn_decode_ba(&OCSPRequest_desc, ocspreq, in));

cleanup:
    return ret;
}

int ocspreq_get_tbsreq(const OCSPRequest_t *ocspreq, TBSRequest_t **tbsreq)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(tbsreq != NULL);
    CHECK_PARAM(*tbsreq == NULL);

    CHECK_NOT_NULL(*tbsreq = asn_copy_with_alloc(&TBSRequest_desc, &ocspreq->tbsRequest));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&TBSRequest_desc, *tbsreq);
        *tbsreq = NULL;
    }

    return ret;
}

int ocspreq_set_tbsreq(OCSPRequest_t *ocspreq, const TBSRequest_t *tbsreq)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(tbsreq != NULL);

    ASN_FREE_CONTENT_STATIC(&TBSRequest_desc, &ocspreq->tbsRequest);
    DO(asn_copy(&TBSRequest_desc, tbsreq, &ocspreq->tbsRequest));

cleanup:

    return ret;
}

int ocspreq_get_sign(const OCSPRequest_t *ocspreq, Signature_t **sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(sign != NULL);
    CHECK_PARAM(*sign == NULL);

    if (!ocspreq->optionalSignature) {
        *sign = NULL;
        return RET_OK;
    }

    CHECK_NOT_NULL(*sign = asn_copy_with_alloc(&Signature_desc, ocspreq->optionalSignature));

cleanup:

    return ret;
}

int ocspreq_set_sign(OCSPRequest_t *ocspreq, const Signature_t *sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(sign != NULL);

    ASN_FREE(&Signature_desc, ocspreq->optionalSignature);
    CHECK_NOT_NULL(ocspreq->optionalSignature = asn_copy_with_alloc(&Signature_desc, sign));

cleanup:

    return ret;
}

int ocspreq_has_sign(const OCSPRequest_t *ocspreq, bool *has_sign)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(has_sign != NULL);

    *has_sign = (NULL != ocspreq->optionalSignature);
cleanup:
    return ret;
}

int ocspreq_verify(const OCSPRequest_t *ocspreq, const VerifyAdapter *adapter)
{
    int ret = RET_OK;

    ByteArray *buffer = NULL;
    ByteArray *sign = NULL;
    bool has_sign = false;

    LOG_ENTRY();

    CHECK_PARAM(ocspreq != NULL);
    CHECK_PARAM(adapter != NULL);

    DO(ocspreq_has_sign(ocspreq, &has_sign));

    if (!has_sign) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_REQ_NO_SIGN);
    }

    DO(asn_encode_ba(&TBSRequest_desc, &ocspreq->tbsRequest, &buffer));
    DO(sign_bs_to_ba(&ocspreq->optionalSignature->signature, &ocspreq->optionalSignature->signatureAlgorithm, &sign));
    DO(adapter->verify_data(adapter, buffer, sign));

cleanup:

    ba_free(sign);
    ba_free(buffer);

    return ret;
}
