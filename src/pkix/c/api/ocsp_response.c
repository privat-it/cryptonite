/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "log_internal.h"
#include "ocsp_response.h"
#include "pkix_utils.h"
#include "pkix_macros_internal.h"
#include "exts.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/ocsp_response.c"

OCSPResponse_t *ocspresp_alloc(void)
{
    OCSPResponse_t *ocspresp = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(ocspresp);

cleanup:

    return ocspresp;
}

void ocspresp_free(OCSPResponse_t *ocspresp)
{
    LOG_ENTRY();

    if (ocspresp) {
        ASN_FREE(&OCSPResponse_desc, ocspresp);
    }
}

int ocspresp_encode(const OCSPResponse_t *ocspresp, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(*out == NULL);

    DO(asn_encode_ba(&OCSPResponse_desc, ocspresp, out));
cleanup:
    return ret;
}

int ocspresp_decode(OCSPResponse_t *ocspresp, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&OCSPResponse_desc, ocspresp);

    DO(asn_decode_ba(&OCSPResponse_desc, ocspresp, in));

cleanup:

    return ret;
}

int ocspresp_get_status(const OCSPResponse_t *ocspresp, OCSPResponseStatus_t **status)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(status != NULL);
    CHECK_PARAM(*status == NULL);

    CHECK_NOT_NULL(*status = asn_copy_with_alloc(&OCSPResponseStatus_desc, &ocspresp->responseStatus));

cleanup:

    return ret;
}

int ocspresp_set_status(OCSPResponse_t *ocspresp, const OCSPResponseStatus_t *status)
{
    int ret = RET_OK;

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(status != NULL);

    ASN_FREE_CONTENT_STATIC(&OCSPResponseStatus_desc, &ocspresp->responseStatus);
    DO(asn_copy(&OCSPResponseStatus_desc, status, &ocspresp->responseStatus));

cleanup:

    return ret;
}

int ocspresp_get_response_bytes(const OCSPResponse_t *ocspresp, ResponseBytes_t **resp_bytes)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(resp_bytes != NULL);
    CHECK_PARAM(*resp_bytes == NULL);

    if (!ocspresp->responseBytes) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_BYTES);
    }

    CHECK_NOT_NULL(*resp_bytes = asn_copy_with_alloc(&ResponseBytes_desc, ocspresp->responseBytes));

cleanup:

    return ret;
}

int ocspresp_set_response_bytes(OCSPResponse_t *ocspresp, const ResponseBytes_t *resp_bytes)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(resp_bytes != NULL);

    ASN_FREE(&ResponseBytes_desc, ocspresp->responseBytes);
    CHECK_NOT_NULL(ocspresp->responseBytes = asn_copy_with_alloc(&ResponseBytes_desc, resp_bytes));

cleanup:

    return ret;
}

int ocspresp_get_certs(const OCSPResponse_t *ocspresp, Certificate_t *** certs, int *certs_len)
{
    int ret = RET_OK;
    int i;
    Certificate_t **certs_ptr = NULL;
    int certs_ptr_len = 0;

    BasicOCSPResponse_t *basic_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(certs != NULL);
    CHECK_PARAM(certs_len != NULL);

    if (!ocspresp->responseBytes) {
        LOG_ENTRY();
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_BYTES);
    }

    CHECK_NOT_NULL(basic_response = asn_decode_with_alloc(&BasicOCSPResponse_desc, ocspresp->responseBytes->response.buf,
            ocspresp->responseBytes->response.size));

    if (basic_response->certs != NULL && basic_response->certs->list.count > 0) {
        certs_ptr_len = basic_response->certs->list.count;
        CALLOC_CHECKED(certs_ptr, certs_ptr_len * sizeof(Certificate_t *));
        for (i = 0; i < certs_ptr_len; i++) {
            CHECK_NOT_NULL(certs_ptr[i] = asn_copy_with_alloc(&Certificate_desc, basic_response->certs->list.array[i]));
        }
        *certs = certs_ptr;
        *certs_len = certs_ptr_len;
        ret = RET_OK;
    } else {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }

cleanup:

    ASN_FREE(&BasicOCSPResponse_desc, basic_response);

    return ret;
}

int ocspresp_get_responder_id(const OCSPResponse_t *ocspresp, ResponderID_t **responderID)
{
    int ret = RET_OK;

    BasicOCSPResponse_t *basic_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(responderID != NULL);

    if (!ocspresp->responseBytes) {
        LOG_ENTRY();
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_BYTES);
    }

    CHECK_NOT_NULL(basic_response = asn_decode_with_alloc(&BasicOCSPResponse_desc,
            ocspresp->responseBytes->response.buf, ocspresp->responseBytes->response.size));
    CHECK_NOT_NULL(*responderID = asn_copy_with_alloc(&ResponderID_desc, &basic_response->tbsResponseData.responderID));

cleanup:

    ASN_FREE(&BasicOCSPResponse_desc, basic_response);

    return ret;
}

int ocspresp_get_certs_status(const OCSPResponse_t *ocspresp, OcspCertStatus *** ocsp_cert_statuses,
        int *ocsp_cert_statuses_len)
{
    int ret = RET_OK;
    BasicOCSPResponse_t *basic_response = NULL;
    OcspCertStatus **ocsp_cert_statuses_ptr = NULL;
    int i = 0;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(ocsp_cert_statuses != NULL);

    if (!ocspresp->responseBytes) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_BYTES);
    }

    LOG_ENTRY();
    CHECK_NOT_NULL(basic_response = asn_decode_with_alloc(&BasicOCSPResponse_desc,
            ocspresp->responseBytes->response.buf, ocspresp->responseBytes->response.size));

    LOG_ENTRY();
    if (basic_response->tbsResponseData.responses.list.count > 0) {
        LOG_ENTRY();
        *ocsp_cert_statuses_len = basic_response->tbsResponseData.responses.list.count;
        CALLOC_CHECKED(ocsp_cert_statuses_ptr, (*ocsp_cert_statuses_len) * sizeof(OcspCertStatus *));
        LOG_ENTRY();
        for (i = 0; i < *ocsp_cert_statuses_len; i++) {
            const CertStatus_t *cert_status;

            LOG_ENTRY();
            CALLOC_CHECKED(ocsp_cert_statuses_ptr[i], sizeof(OcspCertStatus));

            CHECK_NOT_NULL(ocsp_cert_statuses_ptr[i]->serial_number = asn_copy_with_alloc(&CertificateSerialNumber_desc,
                    &basic_response->tbsResponseData.responses.list.array[i]->certID.serialNumber));

            cert_status = &basic_response->tbsResponseData.responses.list.array[i]->certStatus;
            switch (cert_status->present) {
            case CertStatus_PR_good:
                ocsp_cert_statuses_ptr[i]->status = "good";
                ocsp_cert_statuses_ptr[i]->revocationTime = 0;
                ocsp_cert_statuses_ptr[i]->revocationReason = NULL;
                break;
            case CertStatus_PR_revoked:
                ocsp_cert_statuses_ptr[i]->status = "revoked";
                ocsp_cert_statuses_ptr[i]->revocationTime = asn_GT2time(&cert_status->choice.revoked.revocationTime, NULL, false);
                if (cert_status->choice.revoked.revocationReason) {
                    long rev_reason;

                    asn_INTEGER2long(cert_status->choice.revoked.revocationReason, &rev_reason);
                    switch (rev_reason) {
                    case CRLReason_unspecified:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "unspecified";
                        break;
                    case CRLReason_keyCompromise:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "keyCompromise";
                        break;
                    case CRLReason_cACompromise:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "cACompromise";
                        break;
                    case CRLReason_affiliationChanged:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "affiliationChanged";
                        break;
                    case CRLReason_superseded:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "superseded";
                        break;
                    case CRLReason_cessationOfOperation:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "cessationOfOperation";
                        break;
                    case CRLReason_certificateHold:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "certificateHold";
                        break;
                    case CRLReason_removeFromCRL:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "removeFromCRL";
                        break;
                    case CRLReason_privilegeWithdrawn:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "privilegeWithdrawn";
                        break;
                    case CRLReason_aACompromise:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "aACompromise";
                        break;
                    default:
                        ocsp_cert_statuses_ptr[i]->revocationReason = "unknown";
                    }
                } else {
                    ocsp_cert_statuses_ptr[i]->revocationReason = NULL;
                }
                break;
            case CertStatus_PR_unknown:
            default:
                ocsp_cert_statuses_ptr[i]->status = "unknown";
                ocsp_cert_statuses_ptr[i]->revocationTime = 0;
                ocsp_cert_statuses_ptr[i]->revocationReason = NULL;
                break;
            }

        }
        LOG_ENTRY();
        *ocsp_cert_statuses = ocsp_cert_statuses_ptr;
    } else {
        *ocsp_cert_statuses_len = 0;
    }

cleanup:

    LOG_ENTRY();
    ASN_FREE(&BasicOCSPResponse_desc, basic_response);

    return ret;
}

int ocspresp_verify(const OCSPResponse_t *ocspresp, VerifyAdapter *adapter)
{
    int ret = RET_OK;

    ByteArray *buffer = NULL;
    ByteArray *sign = NULL;

    BasicOCSPResponse_t *basic_response = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ocspresp != NULL);
    CHECK_PARAM(adapter != NULL);

    if (!ocspresp->responseBytes) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OCSP_RESP_NO_BYTES);
    }

    CHECK_NOT_NULL(basic_response = asn_decode_with_alloc(&BasicOCSPResponse_desc,
            ocspresp->responseBytes->response.buf, ocspresp->responseBytes->response.size));
    DO(asn_encode_ba(&ResponseData_desc, &basic_response->tbsResponseData, &buffer));
    DO(sign_bs_to_ba(&basic_response->signature, &basic_response->signatureAlgorithm, &sign));
    DO(adapter->verify_data(adapter, buffer, sign));

cleanup:

    ba_free(sign);
    ba_free(buffer);
    ASN_FREE(&BasicOCSPResponse_desc, basic_response);

    return ret;
}

void ocspresp_certs_status_free(OcspCertStatus *ocsp_cert_statuses)
{
    if (ocsp_cert_statuses) {
        ASN_FREE(&CertificateSerialNumber_desc, ocsp_cert_statuses->serial_number);

        free(ocsp_cert_statuses);
    }
}
