/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "cert.h"

#include <time.h>
#include <stdlib.h>

#include "asn1_utils.h"
#include "pkix_utils.h"
#include "oids.h"
#include "spki.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"


#undef FILE_MARKER
#define FILE_MARKER "pki/api/cert.c"

#define SERIAL_LEN 20

Certificate_t *cert_alloc(void)
{
    Certificate_t *cert = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(cert);

cleanup:

    return cert;
}

void cert_free(Certificate_t *cert)
{
    LOG_ENTRY();

    if (cert) {
        ASN_FREE(&Certificate_desc, cert);
    }
}

int cert_init_by_sign(Certificate_t *cert,
        const TBSCertificate_t *tbs_cert,
        const AlgorithmIdentifier_t *aid,
        const BIT_STRING_t *sign)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(tbs_cert != NULL);
    CHECK_PARAM(sign != NULL);
    CHECK_PARAM(aid != NULL);

    DO(asn_copy(&TBSCertificate_desc, tbs_cert, &cert->tbsCertificate));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &cert->signatureAlgorithm));
    DO(asn_copy(&BIT_STRING_desc, sign, &cert->signature));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&Certificate_desc, cert);
    }

    return ret;
}

int cert_init_by_adapter(Certificate_t *cert, const TBSCertificate_t *tbs_cert, const SignAdapter *adapter)
{
    int ret = RET_OK;

    AlgorithmIdentifier_t *aid = NULL;
    ByteArray *sign = NULL;
    ByteArray *tbs_cert_encoded = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(tbs_cert != NULL);
    CHECK_PARAM(adapter != NULL);

    DO(asn_copy(&TBSCertificate_desc, tbs_cert, &cert->tbsCertificate));

    DO(adapter->get_sign_alg(adapter, &aid));
    DO(asn_copy(&AlgorithmIdentifier_desc, aid, &cert->signatureAlgorithm));

    DO(asn_encode_ba(&TBSCertificate_desc, tbs_cert, &tbs_cert_encoded));

    DO(adapter->sign_data(adapter, tbs_cert_encoded, &sign));
    DO(sign_ba_to_bs(sign, &cert->signatureAlgorithm, &cert->signature));

cleanup:

    ba_free(sign);
    ba_free(tbs_cert_encoded);

    ASN_FREE(&AlgorithmIdentifier_desc, aid);

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&Certificate_desc, cert);
    }

    return ret;
}

int cert_encode(const Certificate_t *cert, ByteArray **encode)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(encode != NULL);

    DO(asn_encode_ba(&Certificate_desc, cert, encode));

cleanup:
    return ret;
}

int cert_decode(Certificate_t *cert, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&Certificate_desc, cert);

    DO(asn_decode_ba(&Certificate_desc, cert, in));

cleanup:

    return ret;
}

int cert_has_unsupported_critical_ext(const Certificate_t *cert, bool *flag)
{
    int i, j;
    bool check;
    Extensions_t *cert_extensions;
    int ret = RET_OK;
    const OidNumbers *ext = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = false;

    cert_extensions = cert->tbsCertificate.extensions;

    if (!cert_extensions) {
        return RET_OK;
    }

    if (cert_extensions->list.count <= 0) {
        return RET_OK;
    }

    for (i = 0; i < cert_extensions->list.count; i++) {

        Extension_t *extension = cert_extensions->list.array[i];

        if (!extension) {
            continue;
        }

        if (extension->critical && *(extension->critical) == true) {

            check = false;

            /* Поиск идентификатора в списке поддерживаемых. */
            j = 0;
            while (true) {
                ext = oids_get_supported_extention(j++);
                if (ext == NULL) {
                    break;
                }

                if (pkix_check_oid_parent(&extension->extnID, ext) == true) {
                    check = true;
                    break;
                }
            }

            if (!check) {
                *flag = true;
                return RET_OK;
            }
        }
    }

    *flag = false;

cleanup:

    return ret;
}

int cert_get_critical_ext_oids(const Certificate_t *cert, OBJECT_IDENTIFIER_t ***oids, size_t *cnt)
{
    Extensions_t *cert_exts;
    OBJECT_IDENTIFIER_t **oids_list = NULL;
    int i;
    int count = 0;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(cnt != NULL);

    cert_exts = cert->tbsCertificate.extensions;
    if (!cert_exts) {
        return RET_OK;
    }

    if (cert_exts->list.count <= 0) {
        *cnt = 0;
        return RET_OK;
    }

    /* Подсчет количества критических дополнений. */
    for (count = 0 , i = 0; i < cert_exts->list.count; i++) {

        Extension_t *extension = cert_exts->list.array[i];

        if (!extension || !(extension->critical)) {
            continue;
        }

        if (*(extension->critical)) {
            count++;
        }
    }

    CALLOC_CHECKED(oids_list, count * sizeof(OBJECT_IDENTIFIER_t));


    for (count = 0 , i = 0; i < cert_exts->list.count; i++) {
        Extension_t *extension = cert_exts->list.array[i];

        if (!extension || !(extension->critical)) {
            continue;
        }

        if (*(extension->critical)) {
            CHECK_NOT_NULL(oids_list[count++] = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, &extension->extnID));
        }
    }

    *cnt = count;
    *oids = oids_list;

cleanup:

    if (ret != RET_OK) {
        for (i = 0; i < count; i++) {
            ASN_FREE(&OBJECT_IDENTIFIER_desc, oids_list[i]);
        }
        free(oids_list);
    }

    return ret;
}

int cert_get_non_critical_ext_oids(const Certificate_t *cert, OBJECT_IDENTIFIER_t ***oids, size_t *cnt)
{
    Extensions_t *cert_extensions;
    OBJECT_IDENTIFIER_t **oids_list = NULL;
    int i;
    int count = 0;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(cnt != NULL);

    cert_extensions = cert->tbsCertificate.extensions;
    if (!cert_extensions) {
        *oids = NULL;
        *cnt = 0;
        return RET_OK;
    }

    if (cert_extensions->list.count <= 0) {
        *oids = NULL;
        *cnt = 0;
        return RET_OK;
    }

    /* Подсчет количества не критических дополнений. */
    for (count = 0 , i = 0; i < cert_extensions->list.count; i++) {

        Extension_t *extension = cert_extensions->list.array[i];

        if (!extension) {
            continue;
        }

        if (!extension->critical || *(extension->critical) == false) {
            count++;
        }
    }

    CALLOC_CHECKED(oids_list, count * sizeof(OBJECT_IDENTIFIER_t *));

    for (count = 0, i = 0; i < cert_extensions->list.count; i++) {
        Extension_t *extension = cert_extensions->list.array[i];

        if (!extension) {
            continue;
        }

        if (!extension->critical || *(extension->critical) == false) {
            CHECK_NOT_NULL(oids_list[count] = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, &extension->extnID));
            count++;
        }
    }

    *cnt = count;
    *oids = oids_list;

cleanup:

    if (ret != RET_OK) {
        for (i = 0; i < count; i++) {
            ASN_FREE(&OBJECT_IDENTIFIER_desc, oids_list[i]);
        }
        free(oids_list);
    }

    return ret;
}

int cert_get_ext_value(const Certificate_t *cert, const OidNumbers *oid_numbers, ByteArray **out)
{
    int ret = RET_OK;
    int i;
    Extensions_t *cert_extensions;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(oid_numbers != NULL);
    CHECK_PARAM(out != NULL);

    cert_extensions = cert->tbsCertificate.extensions;

    if (!cert_extensions) {
        SET_ERROR(RET_PKIX_EXT_NOT_FOUND);
    }

    if (cert_extensions->list.count <= 0) {
        SET_ERROR(RET_PKIX_EXT_NOT_FOUND);
    }

    for (i = 0; i < cert_extensions->list.count; i++) {
        Extension_t *extension = cert_extensions->list.array[i];

        if (!extension) {
            continue;
        }

        /* Поиск идентификатора в списке поддерживаемых. */
        if (pkix_check_oid_equal(&extension->extnID, oid_numbers)) {
            CHECK_NOT_NULL(*out = ba_alloc_from_uint8(extension->extnValue.buf, extension->extnValue.size));
            goto cleanup;
        }
    }

    SET_ERROR(RET_PKIX_EXT_NOT_FOUND);

cleanup:

    return ret;
}

int cert_check_validity(const Certificate_t *cert)
{
    int ret = RET_OK;
    time_t current = time(NULL);

    LOG_ENTRY();

    if (current == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }
    DO(cert_check_validity_with_date(cert, current));

cleanup:

    return ret;
}

int cert_check_validity_with_date(const Certificate_t *cert, time_t date)
{
    int ret = RET_OK;
    time_t not_after;
    time_t not_before;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);

    if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_utcTime) {
        not_before = asn_UT2time(&cert->tbsCertificate.validity.notBefore.choice.utcTime, NULL, false);
    } else if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_generalTime) {
        not_before = asn_GT2time(&cert->tbsCertificate.validity.notBefore.choice.generalTime, NULL, false);
    } else {
        not_before = 0;
    }

    if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_utcTime) {
        not_after = asn_UT2time(&cert->tbsCertificate.validity.notAfter.choice.utcTime, NULL, false);
    } else if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_generalTime) {
        not_after = asn_GT2time(&cert->tbsCertificate.validity.notAfter.choice.generalTime, NULL, false);
    } else {
        not_after = 0;
    }

    if (not_before == -1 || not_after == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }

    if (not_before && (not_before > date)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CERT_NOT_BEFORE_VALIDITY_ERROR);

    }
    if (not_after && (not_after < date)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CERT_NOT_AFTER_VALIDITY_ERROR);
    }

cleanup:

    return ret;
}

int cert_get_version(const Certificate_t *cert, long *version)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(version != NULL);

    if (!cert->tbsCertificate.version) {
        *version = 0;
    } else {
        DO(asn_INTEGER2long(cert->tbsCertificate.version, version));
    }

cleanup:

    return ret;
}

int cert_get_sn(const Certificate_t *cert, ByteArray **sn)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(sn != NULL);

    DO(asn_INTEGER2ba(&cert->tbsCertificate.serialNumber, sn));

cleanup:

    if (ret != RET_OK) {
        ba_free(*sn);
        *sn = NULL;
    }

    return ret;
}

int cert_get_not_before(const Certificate_t *cert, time_t *date)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(date != NULL);

    if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_utcTime) {
        *date = asn_UT2time(&cert->tbsCertificate.validity.notBefore.choice.utcTime, NULL, false);
    } else if (cert->tbsCertificate.validity.notBefore.present == PKIXTime_PR_generalTime) {
        *date = asn_GT2time(&cert->tbsCertificate.validity.notBefore.choice.generalTime, NULL, false);
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
    }

    if (*date == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }
cleanup:
    return ret;
}

int cert_get_not_after(const Certificate_t *cert, time_t *date)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(date != NULL);

    if (cert->tbsCertificate.validity.notAfter.present == PKIXTime_PR_utcTime) {
        *date = asn_UT2time(&cert->tbsCertificate.validity.notAfter.choice.utcTime, NULL, false);
    } else if (cert->tbsCertificate.validity.notAfter.present == PKIXTime_PR_generalTime) {
        *date = asn_GT2time(&cert->tbsCertificate.validity.notAfter.choice.generalTime, NULL, false);
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
    }

    if (*date == -1) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_GET_TIME_ERROR);
    }

cleanup:
    return ret;
}

int cert_get_tbs_cert(const Certificate_t *cert, TBSCertificate_t **tbs_cert)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(tbs_cert != NULL);
    CHECK_PARAM(*tbs_cert == NULL);

    CHECK_NOT_NULL(*tbs_cert = asn_copy_with_alloc(&TBSCertificate_desc, &cert->tbsCertificate));

cleanup:

    return ret;
}

int cert_get_tbs_info(const Certificate_t *cert, ByteArray **out)
{
    int ret = RET_OK;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&TBSCertificate_desc, &cert->tbsCertificate, out));
cleanup:
    return ret;
}

int cert_get_aid(const Certificate_t *cert, AlgorithmIdentifier_t **aid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(aid != NULL);

    CHECK_NOT_NULL(*aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, &cert->signatureAlgorithm));

cleanup:

    return ret;
}

int cert_get_sign(const Certificate_t *cert, BIT_STRING_t **sign)
{
    int ret = RET_OK;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(sign != NULL);

    CHECK_NOT_NULL(*sign = asn_copy_with_alloc(&BIT_STRING_desc, &cert->signature));

cleanup:

    return ret;
}

int cert_get_key_usage(const Certificate_t *cert, KeyUsage_t **attr)
{
    int ret = RET_OK;

    ByteArray *ptr = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(attr != NULL);

    DO(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_KEY_USAGE_EXTENSION_ID), &ptr));
    CHECK_NOT_NULL(*attr = asn_decode_ba_with_alloc(&KeyUsage_desc, ptr));

cleanup:

    ba_free(ptr);

    return ret;
}

int cert_get_basic_constrains(const Certificate_t *cert, int *cnt)
{
    int ret = RET_OK;

    int i;
    Extensions_t *extensions = NULL;
    BasicConstraints_t *bc = NULL;
    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(cnt != NULL);

    *cnt = -1;

    extensions = cert->tbsCertificate.extensions;

    if (!extensions) {
        goto cleanup;
    }

    if (extensions->list.count <= 0) {
        goto cleanup;
    }

    ASN_ALLOC(bc);

    for (i = 0; i < extensions->list.count; i++) {
        Extension_t *extension = extensions->list.array[i];

        if (!extension) {
            continue;
        }

        if (pkix_check_oid_equal(&extension->extnID, oids_get_oid_numbers_by_id(OID_BASIC_CONSTRAINTS_EXTENSION_ID))) {
            DO(asn_decode(&BasicConstraints_desc, bc, extension->extnValue.buf, extension->extnValue.size));

            if (bc->pathLenConstraint) {
                long lcnt;
                DO(asn_INTEGER2long(bc->pathLenConstraint, &lcnt));

                *cnt = lcnt;
            }

            break;
        }
    }

cleanup:

    ASN_FREE(&BasicConstraints_desc, bc);

    return ret;
}

int cert_is_ocsp_cert(const Certificate_t *cert, bool *flag)
{
    int ret = RET_OK;

    int i;
    Extensions_t *extensions = NULL;
    ExtendedKeyUsage_t *eku = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(flag != NULL);

    extensions = cert->tbsCertificate.extensions;
    *flag = false;

    if (!extensions) {
        goto cleanup;
    }

    if (extensions->list.count <= 0) {
        goto cleanup;
    }

    ASN_ALLOC(eku);

    for (i = 0; i < extensions->list.count; i++) {
        Extension_t *extension = extensions->list.array[i];

        if (!extension) {
            continue;
        }

        if (pkix_check_oid_equal(&extension->extnID, oids_get_oid_numbers_by_id(OID_EXT_KEY_USAGE_EXTENSION_ID))) {

            DO(asn_decode(&ExtendedKeyUsage_desc, eku, extension->extnValue.buf, extension->extnValue.size));

            if (eku->list.count == 1) {
                KeyPurposeId_t *key_purpose = eku->list.array[0];

                if (pkix_check_oid_parent(key_purpose, oids_get_oid_numbers_by_id(OID_OCSP_KEY_PURPOSE_ID))) {
                    *flag = true;
                }
            }

            break;
        }
    }

cleanup:

    ASN_FREE(&ExtendedKeyUsage_desc, eku);

    return ret;
}

int cert_verify(const Certificate_t *cert, const VerifyAdapter *adapter)
{
    ByteArray *buffer = NULL;
    ByteArray *sign = NULL;
    int ret = RET_OK;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(adapter != NULL);

    LOG_ENTRY();

    DO(asn_encode_ba(&TBSCertificate_desc, &cert->tbsCertificate, &buffer));
    DO(sign_bs_to_ba(&cert->signature, &cert->signatureAlgorithm, &sign));
    DO(adapter->verify_data(adapter, buffer, sign));

cleanup:

    ba_free(sign);
    ba_free(buffer);

    return ret;
}

int cert_get_spki(const Certificate_t *cert, SubjectPublicKeyInfo_t **spki)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(spki != NULL);

    CHECK_NOT_NULL(*spki = asn_copy_with_alloc(&SubjectPublicKeyInfo_desc, &cert->tbsCertificate.subjectPublicKeyInfo));

cleanup:

    return ret;
}

bool cert_check_sid(const Certificate_t *certificate, const SignerIdentifier_t *sid)
{
    SignerIdentifierIm_t *sid_im = NULL;
    ByteArray *cert_subj_key_id = NULL;
    ByteArray *user_subj_key_id = NULL;

    int ret = RET_OK;
    bool ans = false;

    CHECK_PARAM(certificate != NULL);
    CHECK_PARAM(sid != NULL);

    LOG_ENTRY();

    CHECK_NOT_NULL(sid_im = asn_any2type(sid, &SignerIdentifierIm_desc));

    if (sid_im->present == SignerIdentifierIm_PR_issuerAndSerialNumber) {
        if (asn_equals(&CertificateSerialNumber_desc, &certificate->tbsCertificate.serialNumber,
                &sid_im->choice.issuerAndSerialNumber.serialNumber)
                && asn_equals(&Name_desc, &certificate->tbsCertificate.issuer,
                        &sid_im->choice.issuerAndSerialNumber.issuer)) {
            ans = true;
        }
    } else if (sid_im->present == SignerIdentifierIm_PR_subjectKeyIdentifier) {
        DO(cert_get_ext_value(certificate, oids_get_oid_numbers_by_id(OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID),
                &cert_subj_key_id));
        DO(asn_encode_ba(&SubjectKeyIdentifier_desc, &sid_im->choice.subjectKeyIdentifier, &user_subj_key_id));
        if (ba_cmp(cert_subj_key_id, user_subj_key_id) == 0) {
            ans = true;
        }
    }

cleanup:

    ASN_FREE(&SignerIdentifierIm_desc, sid_im);

    ba_free(cert_subj_key_id);
    ba_free(user_subj_key_id);

    return ans;
}

int cert_get_subj_key_id(const Certificate_t *cert, ByteArray **subj_key_id)
{
    ByteArray *cert_subj_key_id = NULL;
    SubjectKeyIdentifier_t *subj_key_id_asn1 = NULL;
    int ret = RET_OK;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(subj_key_id != NULL);

    LOG_ENTRY();

    DO(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID), &cert_subj_key_id));
    CHECK_NOT_NULL(subj_key_id_asn1 = asn_decode_ba_with_alloc(&SubjectKeyIdentifier_desc, cert_subj_key_id));
    DO(asn_OCTSTRING2ba(subj_key_id_asn1, subj_key_id));

cleanup:

    ASN_FREE(&SubjectKeyIdentifier_desc, subj_key_id_asn1);
    ba_free(cert_subj_key_id);

    return ret;
}

int cert_get_auth_key_id(const Certificate_t *cert, ByteArray **auth_key_id)
{
    int ret = RET_OK;
    ByteArray *cert_auth_key_id = NULL;
    AuthorityKeyIdentifier_t *auth_key_id_asn1 = NULL;

    LOG_ENTRY();

    DO(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION_ID), &cert_auth_key_id));
    CHECK_NOT_NULL(auth_key_id_asn1 = asn_decode_ba_with_alloc(&AuthorityKeyIdentifier_desc, cert_auth_key_id));
    DO(asn_OCTSTRING2ba(auth_key_id_asn1->keyIdentifier, auth_key_id));

cleanup:

    ASN_FREE(&AuthorityKeyIdentifier_desc, auth_key_id_asn1);
    ba_free(cert_auth_key_id);

    return ret;
}

int cert_get_qc_statement_limit(const Certificate_t *cert, char **currency_code, long *amount, long *exponent)
{
    int ret;
    QCStatements_t *qcss = NULL;
    ByteArray *qcss_ba = NULL;
    MonetaryValue_t *monetary_value = NULL;
    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    int i;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(currency_code != NULL);
    CHECK_PARAM(amount != NULL);
    CHECK_PARAM(exponent != NULL);

    *amount = 0;
    *exponent = 0;

    DO(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_QC_STATEMENTS_EXTENSION_ID), &qcss_ba));
    CHECK_NOT_NULL(qcss = asn_decode_ba_with_alloc(&QCStatements_desc, qcss_ba));
    for (i = 0; i < qcss->list.count; i++) {
        if (pkix_check_oid_equal(&qcss->list.array[i]->statementId,
                oids_get_oid_numbers_by_id(OID_ETSI_QCS_QC_LIMIT_VALUE_ID))) {
            CHECK_NOT_NULL(monetary_value = asn_any2type(qcss->list.array[i]->statementInfo, &MonetaryValue_desc));
            DO(asn_INTEGER2long(&monetary_value->amount, amount));
            DO(asn_INTEGER2long(&monetary_value->exponent, exponent));
            if (monetary_value->currency.present != Iso4217CurrencyCode_PR_alphabetic) {
                /* Если валюта хранится не строкой. */
                SET_ERROR(RET_PKIX_UNSUPPORTED_ISO4217_CURRENCY_CODE);
            }
            DO(asn_OCTSTRING2bytes(&monetary_value->currency.choice.alphabetic, &bytes, &bytes_len));
            REALLOC_CHECKED(bytes, bytes_len + 1, bytes);
            bytes[bytes_len] = 0;
            *currency_code = (char *)bytes;
            bytes = NULL;

            goto cleanup;
        }
    }

    SET_ERROR(RET_PKIX_CERT_NO_QC_STATEMENT_LIMIT);

cleanup:

    free(bytes);
    ASN_FREE(&MonetaryValue_desc, monetary_value);
    ba_free(qcss_ba);
    ASN_FREE(&QCStatements_desc, qcss);

    return ret;
}

bool cert_check_validity_encode(const ByteArray *cert)
{
    Certificate_t *certificate = NULL;
    bool out = false;
    int ret;

    CHECK_NOT_NULL(certificate = cert_alloc());
    out = (cert_decode(certificate, cert) == RET_OK);

cleanup:

    cert_free(certificate);

    return out;
}

int cert_check_pubkey_and_usage(const Certificate_t *cert, const ByteArray *pub_key, int key_usage, bool *flag)
{
    int ret = RET_OK;

    ByteArray *cert_pub_key = NULL;
    KeyUsage_t *usage = NULL;
    bool is_checked = false;
    int i;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(pub_key != NULL);
    CHECK_PARAM(flag != NULL);

    DO(spki_get_pub_key(&cert->tbsCertificate.subjectPublicKeyInfo, &cert_pub_key));

    if (ba_cmp(cert_pub_key, pub_key)) {
        goto cleanup;
    }

    if (key_usage) {
        DO(cert_get_key_usage(cert, &usage));

        for (i = 0; i < 9; i++) {
            if (key_usage & 0x01) {
                int bit = 0;

                DO(asn_BITSTRING_get_bit(usage, i, &bit));
                if (!bit) {
                    goto cleanup;
                }
            }
            key_usage = key_usage >> 1;
        }
    }

    is_checked = true;

cleanup:

    *flag = is_checked;

    ba_free(cert_pub_key);
    ASN_FREE(&KeyUsage_desc, usage);

    return ret;
}

int cert_get_tsp_url(const Certificate_t *cert, ByteArray **data)
{
    int ret = RET_OK;
    int i;

    SubjectInfoAccess_t *access = NULL;
    ByteArray *encoded = NULL;

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(data != NULL);

    ASN_ALLOC(access);

    DO(cert_get_ext_value(cert, oids_get_oid_numbers_by_id(OID_SUBJECT_INFO_ACCESS_EXTENSION_ID), &encoded));

    if (encoded) {
        DO(asn_decode_ba(&SubjectInfoAccess_desc, access, encoded));

        for (i = 0; i < access->list.count; i++) {
            if (pkix_check_oid_equal(&access->list.array[i]->accessMethod, oids_get_oid_numbers_by_id(OID_TSP_OID_ID))) {
                if (access->list.array[i]->accessLocation.present == GeneralName_PR_uniformResourceIdentifier) {
                    DO(asn_OCTSTRING2ba(&access->list.array[i]->accessLocation.choice.uniformResourceIdentifier, data));
                }
            }
        }
    }

cleanup:

    ASN_FREE(&SubjectInfoAccess_desc, access);

    ba_free(encoded);

    return ret;
}

