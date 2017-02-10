/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "log_internal.h"
#include "content_info.h"
#include "signed_data.h"
#include "tsp_response.h"
#include "pkix_macros_internal.h"


#undef FILE_MARKER
#define FILE_MARKER "pki/api/tsp_response.c"

TimeStampResp_t *tsresp_alloc(void)
{
    TimeStampResp_t *tsresp = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(tsresp);

cleanup:

    return tsresp;
}

void tsresp_free(TimeStampResp_t *tsresp)
{
    LOG_ENTRY();

    if (tsresp) {
        ASN_FREE(&TimeStampResp_desc, tsresp);
    }
}

int tsresp_encode(const TimeStampResp_t *tsresp, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&TimeStampResp_desc, tsresp, out));
cleanup:
    return ret;
}

int tsresp_decode(TimeStampResp_t *tsresp, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(in != NULL);

    LOG_BYTES(LOG_ALWAYS, "valgrind need additional test in", in, len);
    ASN_FREE_CONTENT_PTR(&TimeStampResp_desc, tsresp);
    DO(asn_decode_ba(&TimeStampResp_desc, tsresp, in));

cleanup:
    return ret;
}

int tsresp_get_status(const TimeStampResp_t *tsresp, PKIStatusInfo_t **status)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(status != NULL);
    CHECK_PARAM(*status == NULL);

    CHECK_NOT_NULL(*status = asn_copy_with_alloc(&PKIStatusInfo_desc, &tsresp->status));

cleanup:

    return ret;
}

int tsresp_set_status(TimeStampResp_t *tsresp, const PKIStatusInfo_t *status)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(status != NULL);

    ASN_FREE_CONTENT_STATIC(&PKIStatusInfo_desc, &tsresp->status);

    DO(asn_copy(&PKIStatusInfo_desc, status, &tsresp->status));

cleanup:

    return ret;
}

int tsresp_get_ts_token(const TimeStampResp_t *tsresp, ContentInfo_t **ts_token)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(ts_token != NULL);
    CHECK_PARAM(*ts_token == NULL);

    if (!tsresp->timeStampToken) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_TSP_RESP_NO_TS_TOKEN);
    }

    CHECK_NOT_NULL(*ts_token = asn_copy_with_alloc(&ContentInfo_desc, tsresp->timeStampToken));

cleanup:

    return ret;
}

int tsresp_set_ts_token(TimeStampResp_t *tsresp, const ContentInfo_t *ts_token)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(ts_token != NULL);

    ASN_FREE(&ContentInfo_desc, tsresp->timeStampToken);
    CHECK_NOT_NULL(tsresp->timeStampToken = asn_copy_with_alloc(&ContentInfo_desc, ts_token));

cleanup:

    return ret;
}

int tsresp_verify(const TimeStampResp_t *tsresp, const DigestAdapter *da, const VerifyAdapter *va)
{
    int ret = RET_OK;
    SignedData_t *sdata = NULL;

    LOG_ENTRY();

    CHECK_PARAM(tsresp != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);

    if (!tsresp->timeStampToken) {
        SET_ERROR(RET_PKIX_TSP_RESP_NO_TS_TOKEN);
    }

    DO(cinfo_get_signed_data(tsresp->timeStampToken, &sdata));
    DO(sdata_verify_internal_data_by_adapter(sdata, da, va, 0));

cleanup:

    ASN_FREE(&SignedData_desc, sdata);

    return ret;
}
