/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "crl.h"

#include <stdlib.h>

#include "asn1_utils.h"
#include "log_internal.h"
#include "oids.h"
#include "pkix_macros_internal.h"
#include "pkix_utils.h"
#include "exts.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/crl.c"

CertificateList_t *crl_alloc(void)
{
    CertificateList_t *crl = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(crl);

cleanup:

    return crl;
}

void crl_free(CertificateList_t *crl)
{
    LOG_ENTRY();

    ASN_FREE(&CertificateList_desc, crl);
}

int crl_init_by_sign(CertificateList_t *crl,
        const TBSCertList_t *tbs_crl,
        const AlgorithmIdentifier_t *aid,
        const BIT_STRING_t *sign)
{
    int ret = RET_OK;

    LOG_ENTRY();


    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(tbs_crl != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sign != NULL);

    ASN_FREE_CONTENT_PTR(&CertificateList_desc, crl);

    DO(asn_copy(&TBSCertList_desc, tbs_crl, &crl->tbsCertList));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &crl->signatureAlgorithm));
    DO(asn_copy(&BIT_STRING_desc, sign, &crl->signatureValue));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&CertificateList_desc, crl);
    }

    return ret;
}

int crl_init_by_adapter(CertificateList_t *crl, const TBSCertList_t *tbs_crl, const SignAdapter *adapter)
{
    int ret = RET_OK;

    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *sign = NULL;
    ByteArray *tbs_clist_encoded = NULL;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(tbs_crl != NULL);
    CHECK_PARAM(adapter != NULL);

    ASN_FREE_CONTENT_PTR(&CertificateList_desc, crl);

    DO(asn_copy(&TBSCertList_desc, tbs_crl, &crl->tbsCertList));

    DO(adapter->get_sign_alg(adapter, &aid));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &crl->signatureAlgorithm));

    DO(asn_encode_ba(&TBSCertList_desc, tbs_crl, &tbs_clist_encoded));
    DO(adapter->sign_data(adapter, tbs_clist_encoded, &sign));
    DO(sign_ba_to_bs(sign, &crl->signatureAlgorithm, &crl->signatureValue));

cleanup:

    ba_free(sign);
    ba_free(tbs_clist_encoded);

    ASN_FREE(&AlgorithmIdentifier_desc, aid);

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&CertificateList_desc, crl);
    }

    return ret;
}

int crl_encode(const CertificateList_t *crl, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&CertificateList_desc, crl, out));
cleanup:
    return ret;
}

int crl_decode(CertificateList_t *crl, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&CertificateList_desc, crl);

    DO(asn_decode_ba(&CertificateList_desc, crl, in));

cleanup:
    return ret;
}

int crl_get_tbs(const CertificateList_t *crl, TBSCertList_t **tbs_crl)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(tbs_crl != NULL);

    CHECK_NOT_NULL(*tbs_crl = asn_copy_with_alloc(&TBSCertList_desc, &crl->tbsCertList));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&TBSCertList_desc, *tbs_crl);
    }

    return ret;
}

int crl_set_tbs(CertificateList_t *crl, const TBSCertList_t *tbs_crl)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(tbs_crl != NULL);

    ASN_FREE_CONTENT_STATIC(&TBSCertList_desc, &crl->tbsCertList);

    DO(asn_copy(&TBSCertList_desc, tbs_crl, &crl->tbsCertList));

cleanup:

    return ret;
}

int crl_get_sign_aid(const CertificateList_t *crl, AlgorithmIdentifier_t **aid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(*aid == NULL);

    CHECK_NOT_NULL(*aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &crl->signatureAlgorithm));

cleanup:

    return ret;
}

int crl_set_sign_aid(CertificateList_t *crl, const AlgorithmIdentifier_t *aid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(aid != NULL);

    ASN_FREE_CONTENT_STATIC(&AlgorithmIdentifier_desc, &crl->signatureAlgorithm);

    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &crl->signatureAlgorithm));

cleanup:

    return ret;
}

int crl_get_sign(const CertificateList_t *crl, BIT_STRING_t **sign)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(sign != NULL);

    CHECK_NOT_NULL(*sign = asn_copy_with_alloc(&BIT_STRING_desc, &crl->signatureValue));

cleanup:

    return ret;
}

int crl_set_sign(CertificateList_t *crl, const BIT_STRING_t *sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(sign != NULL);

    ASN_FREE_CONTENT_STATIC(&BIT_STRING_desc, &crl->signatureValue);

    DO(asn_copy(&BIT_STRING_desc, sign, &crl->signatureValue));

cleanup:

    return ret;
}

int crl_check_cert(const CertificateList_t *crl, const Certificate_t *cert, bool *flag)
{
    int ret = RET_OK;
    int i;

    RevokedCertificates_t *revoked_certs;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(flag != NULL);

    revoked_certs = crl->tbsCertList.revokedCertificates;
    *flag = false;

    if (!revoked_certs) {
        return RET_OK;
    }

    if (revoked_certs->list.count <= 0) {
        return RET_OK;
    }

    for (i = 0; i < revoked_certs->list.count; i++) {
        RevokedCertificate_t *revokedCertificate = revoked_certs->list.array[i];

        if (!revokedCertificate) {
            continue;
        }

        if (asn_equals(&CertificateSerialNumber_desc,
                &cert->tbsCertificate.serialNumber,
                &revokedCertificate->userCertificate)) {

            *flag = true;
            return RET_OK;
        }
    }
cleanup:
    return ret;
}

int crl_get_cert_info(const CertificateList_t *crl, const Certificate_t *cert, RevokedCertificate_t **rc)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(rc != NULL);

    DO(crl_get_cert_info_by_sn(crl, &cert->tbsCertificate.serialNumber, rc));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&RevokedCertificate_desc, *rc);
        *rc = NULL;
    }

    return ret;
}

int crl_get_cert_info_by_sn(const CertificateList_t *crl, const INTEGER_t *cert_sn, RevokedCertificate_t **rc)
{
    int ret = RET_OK;
    int i;

    RevokedCertificates_t *revoked_certs = NULL;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(cert_sn != NULL);
    CHECK_PARAM(rc != NULL);

    revoked_certs = crl->tbsCertList.revokedCertificates;

    if (!revoked_certs) {
        SET_ERROR(RET_PKIX_OBJ_NOT_FOUND);
    }

    if (revoked_certs->list.count <= 0) {
        SET_ERROR(RET_PKIX_OBJ_NOT_FOUND);
    }

    for (i = 0; i < revoked_certs->list.count; i++) {
        RevokedCertificate_t *revokedCertificate = revoked_certs->list.array[i];

        if (!revokedCertificate) {
            continue;
        }

        if (asn_equals(&INTEGER_desc, cert_sn, &revokedCertificate->userCertificate)) {
            CHECK_NOT_NULL(*rc = asn_copy_with_alloc(&RevokedCertificate_desc, revokedCertificate));
            goto cleanup;
        }
    }

    SET_ERROR(RET_PKIX_OBJ_NOT_FOUND);

cleanup:

    return ret;
}

int crl_is_full(const CertificateList_t *crl, bool *flag)
{
    int ret = RET_OK;
    int i;

    Extensions_t *crl_exts;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(flag != NULL);

    crl_exts = crl->tbsCertList.crlExtensions;
    *flag = false;

    if (!crl_exts) {
        return RET_OK;
    }

    if (crl_exts->list.count <= 0) {
        return RET_OK;
    }

    for (i = 0; i < crl_exts->list.count; i++) {
        Extension_t *extension = crl_exts->list.array[i];

        if (!extension) {
            continue;
        }

        if (pkix_check_oid_equal(&extension->extnID, oids_get_oid_numbers_by_id(OID_FRESHEST_CRL_EXTENSION_ID))) {
            *flag = true;
            return RET_OK;
        }
    }
cleanup:
    return ret;
}

int crl_is_delta(const CertificateList_t *crl, bool *flag)
{
    int i;
    int ret = RET_OK;

    Extensions_t *crl_exts;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(flag != NULL);

    crl_exts = crl->tbsCertList.crlExtensions;
    *flag = false;

    if (!crl_exts) {
        return RET_OK;
    }

    if (crl_exts->list.count <= 0) {
        return RET_OK;
    }

    for (i = 0; i < crl_exts->list.count; i++) {
        Extension_t *extension = crl_exts->list.array[i];

        if (!extension) {
            continue;
        }

        if (pkix_check_oid_equal(&extension->extnID, oids_get_oid_numbers_by_id(OID_DELTA_CRL_INDICATOR_EXTENSION_ID))) {
            *flag = true;
            return RET_OK;
        }
    }
cleanup:
    return ret;
}

int crl_verify(const CertificateList_t *crl, const VerifyAdapter *adapter)
{
    int ret = RET_OK;

    ByteArray *buffer = NULL;
    ByteArray *sign = NULL;

    LOG_ENTRY();

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(adapter != NULL);

    DO(asn_encode_ba(&TBSCertList_desc, &crl->tbsCertList, &buffer));
    DO(sign_bs_to_ba(&crl->signatureValue, &crl->signatureAlgorithm, &sign));
    DO(adapter->verify_data(adapter, buffer, sign));

cleanup:

    ba_free(sign);
    ba_free(buffer);

    return ret;
}

int crl_get_crl_number(const CertificateList_t *crl, ByteArray **crl_number)
{
    int ret = RET_OK;
    ByteArray *crl_number_ba = NULL;
    CRLNumber_t *crl_number_asn = NULL;

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(crl_number != NULL);

    DO(exts_get_ext_value_by_oid(crl->tbsCertList.crlExtensions, oids_get_oid_numbers_by_id(OID_CRL_NUMBER_EXTENSION_ID),
            &crl_number_ba));
    CHECK_NOT_NULL(crl_number_asn = asn_decode_ba_with_alloc(&CRLNumber_desc, crl_number_ba));
    DO(asn_INTEGER2ba(crl_number_asn, crl_number));

cleanup:

    ba_free(crl_number_ba);
    ASN_FREE(&CRLNumber_desc, crl_number_asn);

    return ret;
}
int crl_get_distribution_points(const CertificateList_t *crl, char ***url, size_t *url_len)
{
    int ret = RET_OK;
    ByteArray *value = NULL;
    CRLDistributionPoints_t *dps = NULL;
    char **url_out = NULL;
    size_t url_len_out = 0;
    char *distr_point = NULL;
    size_t distr_point_len = 0;
    int i, j;

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(url != NULL);
    CHECK_PARAM(url_len != NULL);

    DO(exts_get_ext_value_by_oid(crl->tbsCertList.crlExtensions,
            oids_get_oid_numbers_by_id(OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID),
            &value));
    CHECK_NOT_NULL(dps = asn_decode_ba_with_alloc(&CRLDistributionPoints_desc, value));

    if (dps->list.count <= 0) {
        *url = NULL;
        *url_len = 0;
    }

    CALLOC_CHECKED(url_out, dps->list.count);
    for (i = 0; i < dps->list.count; i++) {
        if (dps->list.array[i]->distributionPoint->present == DistributionPointName_PR_fullName) {
            for (j = 0; j < dps->list.array[i]->distributionPoint->choice.fullName.list.count; j++) {
                if (dps->list.array[i]->distributionPoint->choice.fullName.list.array[j]->present ==
                        GeneralName_PR_uniformResourceIdentifier) {
                    DO(asn_OCTSTRING2bytes(
                            &dps->list.array[i]->distributionPoint->choice.fullName.list.array[j]->choice.uniformResourceIdentifier,
                            (unsigned char **)&distr_point, &distr_point_len));
                    distr_point_len++;
                    REALLOC_CHECKED(distr_point, distr_point_len, distr_point);
                    distr_point[distr_point_len - 1] = '\0';
                    url_len_out++;
                    REALLOC_CHECKED(url_out, url_len_out * sizeof(char *), url_out);
                    url_out[url_len_out - 1] = distr_point;
                    distr_point = NULL;
                }
            }
        }
    }

    *url = url_out;
    *url_len = url_len_out;

cleanup:

    ba_free(value);
    ASN_FREE(&CRLDistributionPoints_desc, dps);

    return ret;
}

int crl_get_this_update(const CertificateList_t *crl, time_t *this_update)
{
    int ret = RET_OK;

    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(this_update != NULL);

    if (crl->tbsCertList.thisUpdate.present != PKIXTime_PR_generalTime) {
        *this_update = asn_UT2time(&crl->tbsCertList.thisUpdate.choice.utcTime, NULL, false);
    } else {
        *this_update = asn_GT2time(&crl->tbsCertList.thisUpdate.choice.generalTime, NULL, false);
    }

cleanup:

    return ret;
}
