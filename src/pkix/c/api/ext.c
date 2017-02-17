/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ext.h"

#include "pkix_macros_internal.h"
#include "log_internal.h"
#include "asn1_utils.h"
#include "pkix_utils.h"
#include "cert.h"
#include "crl.h"
#include "cryptonite_manager.h"
#include "exts.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/ext.c"

#define RND_BYTES 20

/** Преобразование типов OID. */
#define EXT2OID(oid, OID_) DO(OBJECT_IDENTIFIER_set_arcs(&(OID_), (oid)->numbers, sizeof(long), (unsigned int)(oid)->numbers_len));

/** Инициализирует заголовок расширения по константам из oids.h (без значения). */
#define INIT_EXTENSION(ext, oid_id, critical_) DO(init_extension_((ext), oids_get_oid_numbers_by_id(oid_id), (critical_)));

/** Инициализирует заголовок расширения (без значения). */
static int init_extension_(Extension_t **ext, const OidNumbers *oid, bool critical)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(ext != NULL);
    CHECK_PARAM(oid->numbers != NULL);

    ASN_ALLOC(*ext);

    EXT2OID(oid, (*ext)->extnID);
    if (critical) {
        ASN_ALLOC((*ext)->critical);
        *(*ext)->critical = critical;
    }

cleanup:

    /* Do not free *ext here. */
    return ret;
}

/** Преобразует объект указанного типа в OCTERT_STRING. */
static int type_to_octstring(asn_TYPE_descriptor_t *type, const void *src, OCTET_STRING_t *dst)
{
    int ret = RET_OK;
    uint8_t *buffer = NULL;
    size_t len;

    CHECK_PARAM(dst != NULL);

    DO(asn_encode(type, src, &buffer, &len));
    DO(asn_create_octstring(buffer, len, &dst));

cleanup:

    free(buffer);

    return ret;
}

int ext_create_any(bool critical, OidNumbers *oid, const ByteArray *value, Extension_t **ext)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(value != NULL);

    DO(init_extension_(ext, oid, critical));
    DO(asn_ba2OCTSTRING(value, &(*ext)->extnValue));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_auth_key_id_from_spki(bool critical,
        const SubjectPublicKeyInfo_t *spki,
        Extension_t **ext)
{
    int ret = RET_OK;

    AuthorityKeyIdentifier_t *aki = NULL;
    ByteArray *pkbytes = NULL;
    ByteArray *hash = NULL;
    DigestAdapter *da = NULL;

    LOG_ENTRY();

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(ext != NULL);

    ASN_ALLOC(aki);
    INIT_EXTENSION(ext, OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION_ID, critical);

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &pkbytes));
    DO(digest_adapter_init_by_aid(&spki->algorithm, &da));

    DO(da->update(da, pkbytes));
    DO(da->final(da, &hash));

    ASN_ALLOC(aki->keyIdentifier);
    DO(asn_ba2OCTSTRING(hash, aki->keyIdentifier));
    DO(type_to_octstring(&AuthorityKeyIdentifier_desc, aki, &(*ext)->extnValue));

cleanup:

    digest_adapter_free(da);

    ba_free(pkbytes);
    ba_free(hash);

    ASN_FREE(&AuthorityKeyIdentifier_desc, aki);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_auth_key_id_from_cert(bool critical, const Certificate_t *issuer_cert, Extension_t **ext)
{
    int ret = RET_OK;
    AuthorityKeyIdentifier_t *aki = NULL;
    ByteArray *data = NULL;

    LOG_ENTRY();
    CHECK_PARAM(issuer_cert != NULL);

    ASN_ALLOC(aki);
    INIT_EXTENSION(ext, OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION_ID, critical);

    DO(cert_get_ext_value(issuer_cert, oids_get_oid_numbers_by_id(OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID), &data));
    CHECK_NOT_NULL(aki->keyIdentifier = asn_decode_ba_with_alloc(&KeyIdentifier_desc, data));
    DO(type_to_octstring(&AuthorityKeyIdentifier_desc, aki, &(*ext)->extnValue));

cleanup:

    ba_free(data);

    ASN_FREE(&AuthorityKeyIdentifier_desc, aki);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_auth_info_access(bool critical, OidNumbers **oids, const char **name_uris, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    AuthorityInfoAccessSyntax_t *aias = NULL;
    AccessDescription_t *ad = NULL;
    Extension_t *out = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(name_uris != NULL);
    CHECK_PARAM(cnt != 0);
    CHECK_PARAM(ext != NULL);

    for (i = 0; i < cnt; ++i) {
        if (!oids[i]->numbers || !name_uris[i]) {
            LOG_ERROR();
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(aias);
    INIT_EXTENSION(&out, OID_AUTHORITY_INFO_ACCESS_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        ASN_ALLOC(ad);

        ad->accessLocation.present = GeneralName_PR_uniformResourceIdentifier;
        DO(OCTET_STRING_fromString(&ad->accessLocation.choice.uniformResourceIdentifier, name_uris[i]));
        EXT2OID(oids[i], ad->accessMethod);

        DO(ASN_SEQUENCE_ADD(&aias->list, ad));
        ad = NULL;
    }

    DO(type_to_octstring(&AuthorityInfoAccessSyntax_desc, aias, &out->extnValue));

    *ext = out;
    out = NULL;

cleanup:

    ASN_FREE(&AuthorityInfoAccessSyntax_desc, aias);
    ASN_FREE(&AccessDescription_desc, ad);
    ASN_FREE(&Extension_desc, out);

    return ret;
}

int ext_create_basic_constraints(bool critical,
        const BasicConstraints_t *issuer,
        bool ca,
        int path_len_constraint,
        Extension_t **ext)
{
    int ret = RET_OK;
    BasicConstraints_t bc;

    LOG_ENTRY();

    memset(&bc, 0, sizeof(bc));
    INIT_EXTENSION(ext, OID_BASIC_CONSTRAINTS_EXTENSION_ID, critical);

    if (ca) {
        ASN_ALLOC(bc.cA);
        *bc.cA = ca;

        if (!issuer) {
            DO(asn_create_integer_from_long(path_len_constraint, &bc.pathLenConstraint));
        } else {
            long i;

            DO(asn_INTEGER2long(issuer->pathLenConstraint, &i));
            i += 1;
            DO(asn_create_integer_from_long(i, &bc.pathLenConstraint));
        }
    }

    DO(type_to_octstring(&BasicConstraints_desc, &bc, &(*ext)->extnValue));

cleanup:

    ASN_FREE_CONTENT_STATIC(&BasicConstraints_desc, &bc);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_cert_policies(bool critical, OidNumbers **oids, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    CertificatePolicies_t* cp = NULL;
    PolicyInformation_t *pi = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(cnt != 0);

    for (i = 0; i < cnt; ++i) {
        if (!oids[i]->numbers) {
            LOG_ERROR();
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(cp);
    INIT_EXTENSION(ext, OID_CERTIFICATE_POLICIES_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        ASN_ALLOC(pi);
        EXT2OID(oids[i], pi->policyIdentifier);
        DO(ASN_SEQUENCE_ADD(&cp->list, pi));
        pi = NULL;
    }

    DO(type_to_octstring(&CertificatePolicies_desc, cp, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&CertificatePolicies_desc, cp);
    ASN_FREE(&PolicyInformation_desc, pi);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_crl_distr_points(bool critical, const char **point_uris, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    CRLDistributionPoints_t *dps = NULL;
    DistributionPoint_t *dp = NULL;
    GeneralName_t *gn = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(point_uris != NULL);
    CHECK_PARAM(cnt != 0);

    for (i = 0; i < cnt; ++i) {
        if (!point_uris[i]) {
            LOG_ERROR();
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(dps);
    INIT_EXTENSION(ext, OID_CRL_DISTRIBUTION_POINTS_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        ASN_ALLOC(gn);
        gn->present = GeneralName_PR_uniformResourceIdentifier;
        DO(OCTET_STRING_fromString(&gn->choice.uniformResourceIdentifier, point_uris[i]));

        ASN_ALLOC(dp);
        ASN_ALLOC(dp->distributionPoint);
        dp->distributionPoint->present = DistributionPointName_PR_fullName;
        DO(ASN_SEQUENCE_ADD(&dp->distributionPoint->choice.fullName.list, gn));
        gn = NULL;

        DO(ASN_SEQUENCE_ADD(&dps->list, dp));
        dp = NULL;
    }

    DO(type_to_octstring(&CRLDistributionPoints_desc, dps, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&CRLDistributionPoints_desc, dps);
    ASN_FREE(&DistributionPoint_desc, dp);
    ASN_FREE(&GeneralName_desc, gn);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_crl_id(bool critical, char *distr_url, ByteArray *crl_number, time_t *crl_time, Extension_t **ext)
{
    int ret = RET_OK;
    CrlID_t *crlid = NULL;
    Extension_t *crl_id_ext = NULL;

    LOG_ENTRY();

    CHECK_PARAM(ext != NULL);

    ASN_ALLOC(crlid);
    INIT_EXTENSION(&crl_id_ext, OID_CRL_ID_EXTENSION_ID, critical);

    if (crl_time != NULL) {
        CHECK_NOT_NULL(crlid->crlTime = asn_time2GT(NULL, localtime(crl_time), true));
    }

    if (distr_url != NULL) {
        ASN_ALLOC(crlid->crlUrl);
        asn_bytes2OCTSTRING(crlid->crlUrl, (const unsigned char *)distr_url, strlen(distr_url));
    }

    if (crl_number != NULL) {
        DO(asn_create_integer_from_ba(crl_number, &crlid->crlNum));
    }

    DO(type_to_octstring(&CrlID_desc, crlid, &crl_id_ext->extnValue));

    *ext = crl_id_ext;
    crl_id_ext = NULL;

cleanup:

    ASN_FREE(&CrlID_desc, crlid);
    ASN_FREE(&Extension_desc, crl_id_ext);

    return ret;
}

int ext_create_crl_number(bool critical, const ByteArray *crl_sn, Extension_t **ext)
{
    int ret = RET_OK;
    CRLNumber_t *num = NULL;
    Extension_t *crl_number_ext = NULL;

    LOG_ENTRY();

    CHECK_PARAM(crl_sn != NULL);
    CHECK_PARAM(ext != NULL);

    INIT_EXTENSION(&crl_number_ext, OID_CRL_NUMBER_EXTENSION_ID, critical);

    DO(asn_create_integer_from_ba(crl_sn, &num));
    DO(type_to_octstring(&CRLNumber_desc, num, &crl_number_ext->extnValue));

    *ext = crl_number_ext;
    crl_number_ext = NULL;

cleanup:

    ASN_FREE(&CRLNumber_desc, num);
    ASN_FREE(&Extension_desc, crl_number_ext);

    return ret;
}

int ext_create_crl_reason(bool critical, const CRLReason_t *reason, Extension_t **ext)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(reason != NULL);
    CHECK_PARAM(ext != NULL);

    INIT_EXTENSION(ext, OID_CRL_REASON_EXTENSION_ID, critical);
    DO(type_to_octstring(&CRLReason_desc, reason, &(*ext)->extnValue));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }


    return ret;
}

int ext_create_delta_crl_indicator(bool critical, const ByteArray *crl_number, Extension_t **ext)
{
    int ret = RET_OK;
    CRLNumber_t *num = NULL;
    Extension_t *delta_crl_indic_ext = NULL;

    LOG_ENTRY();

    CHECK_PARAM(crl_number != NULL);
    CHECK_PARAM(ext != NULL);

    INIT_EXTENSION(&delta_crl_indic_ext, OID_DELTA_CRL_INDICATOR_EXTENSION_ID, critical);
    DO(asn_create_integer_from_ba(crl_number, &num));
    DO(type_to_octstring(&CRLNumber_desc, num, &delta_crl_indic_ext->extnValue));

    *ext = delta_crl_indic_ext;
    delta_crl_indic_ext = NULL;

cleanup:

    ASN_FREE(&CRLNumber_desc, num);
    ASN_FREE(&Extension_desc, delta_crl_indic_ext);

    return ret;
}

int ext_create_ext_key_usage(bool critical, OBJECT_IDENTIFIER_t **oids, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    int i;
    ExtendedKeyUsage_t *eku = NULL;
    KeyPurposeId_t *kp = NULL;
    Extension_t *extended_key_usage_ext = NULL;

    LOG_ENTRY();

    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(cnt != 0);

    for (i = 0; i < cnt; ++i) {
        if (oids[i] == NULL) {
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(eku);
    INIT_EXTENSION(&extended_key_usage_ext, OID_EXT_KEY_USAGE_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        CHECK_NOT_NULL(kp = asn_copy_with_alloc(&OBJECT_IDENTIFIER_desc, oids[i]));
        DO(ASN_SEQUENCE_ADD(&eku->list, kp));
        kp = NULL;
    }

    DO(type_to_octstring(&ExtendedKeyUsage_desc, eku, &extended_key_usage_ext->extnValue));

    *ext = extended_key_usage_ext;
    extended_key_usage_ext = NULL;

cleanup:

    ASN_FREE(&KeyPurposeId_desc, kp);
    ASN_FREE(&ExtendedKeyUsage_desc, eku);
    ASN_FREE(&Extension_desc, extended_key_usage_ext);

    return ret;
}

int ext_create_freshest_crl(bool critical, const char **point_uris, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    FreshestCRL_t *dps = NULL;
    DistributionPoint_t *dp = NULL;
    GeneralName_t *gn = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(point_uris != NULL);
    CHECK_PARAM(cnt != 0);

    for (i = 0; i < cnt; ++i) {
        if (!point_uris[i]) {
            LOG_ERROR();
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(dps);
    INIT_EXTENSION(ext, OID_FRESHEST_CRL_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        ASN_ALLOC(gn);
        gn->present = GeneralName_PR_uniformResourceIdentifier;
        DO(OCTET_STRING_fromString(&gn->choice.uniformResourceIdentifier, point_uris[i]));

        ASN_ALLOC(dp);
        ASN_ALLOC(dp->distributionPoint);
        dp->distributionPoint->present = DistributionPointName_PR_fullName;
        DO(ASN_SEQUENCE_ADD(&dp->distributionPoint->choice.fullName.list, gn));
        gn = NULL;

        DO(ASN_SEQUENCE_ADD(&dps->list, dp));
        dp = NULL;
    }

    DO(type_to_octstring(&FreshestCRL_desc, dps, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&FreshestCRL_desc, dps);
    ASN_FREE(&DistributionPoint_desc, dp);
    ASN_FREE(&GeneralName_desc, gn);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_invalidity_date(bool critical, const time_t *date, Extension_t **ext)
{
    int ret = RET_OK;
    GeneralizedTime_t *gen_time = NULL;
    Extension_t *extension = NULL;

    LOG_ENTRY();

    CHECK_PARAM(date != NULL);

    INIT_EXTENSION(&extension, OID_INVALIDITY_DATE_EXTENSION_ID, critical);
    CHECK_NOT_NULL(gen_time = asn_time2GT(NULL, localtime(date), true));
    DO(type_to_octstring(&GeneralizedTime_desc, gen_time, &extension->extnValue));

    *ext = extension;
    extension = NULL;

cleanup:

    ASN_FREE(&Extension_desc, extension);
    ASN_FREE(&GeneralizedTime_desc, gen_time);

    return ret;
}

static int byte_bitpadding(uint8_t a)
{
    int i = 0;

    while (0 == (a & (1 << i))) {
        i++;
    }

    return i;
}

/**
 * Переворачивает биты в байте.
 */
static uint8_t swap_bits(uint8_t byte)
{
    int i;
    unsigned char res = 0;

    if (byte != 0) {
        for (i = 0; i < 8; i++) {
            res |= ((byte >> i) & 0x01) << (7 - i);
        }
    }

    return res;
}

int ext_create_key_usage(bool critical, KeyUsageBits usage_bits, Extension_t **ext)
{
    int ret = RET_OK;

    KeyUsage_t ku;
    uint32_t tmp = (uint32_t)usage_bits;
    uint8_t bits[sizeof(tmp) + 1] = {0};
    int bits_len = sizeof(bits) - 1;
    int bits_unused;

    LOG_ENTRY();

    memset(&ku, 0, sizeof(ku));
    INIT_EXTENSION(ext, OID_KEY_USAGE_EXTENSION_ID, critical);

    bits[1] = swap_bits(tmp & 0xff);
    bits[2] = swap_bits((tmp >> 8) & 0xff);
    bits[3] = swap_bits((tmp >> 16) & 0xff);
    bits[4] = swap_bits((tmp >> 24) & 0xff);
    while (bits[bits_len] == 0) {
        bits_len--;
    }

    bits_unused = byte_bitpadding(bits[bits_len]);

    DO(asn_bytes2BITSTRING(bits + 1, &ku, bits_len));
    ku.bits_unused = bits_unused;

    DO(type_to_octstring(&KeyUsage_desc, &ku, &(*ext)->extnValue));

cleanup:

    ASN_FREE_CONTENT_STATIC(&KeyUsage_desc, &ku);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_private_key_usage(bool critical,
        const Validity_t *validity,
        const time_t *not_before,
        const time_t *not_after,
        Extension_t **ext)
{
    int ret = RET_OK;

    PrivateKeyUsagePeriod_t *pkup = NULL;
    GeneralizedTime_t *asn_gt = NULL;
    time_t t_utc;

    LOG_ENTRY();

    CHECK_PARAM(ext != NULL);
    if (!validity) {
        CHECK_PARAM(not_before != NULL);
        CHECK_PARAM(not_after != NULL);
    }

    ASN_ALLOC(pkup);
    INIT_EXTENSION(ext, OID_PRIVATE_KEY_USAGE_PERIOD_EXTENSION_ID, critical);

    if (validity) {
        if (validity->notBefore.present == PKIXTime_PR_NOTHING || validity->notAfter.present == PKIXTime_PR_NOTHING) {
            LOG_ERROR();
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
        }

        switch (validity->notBefore.present) {
        case PKIXTime_PR_utcTime:
            t_utc = asn_UT2time(&validity->notBefore.choice.utcTime, NULL, false);
            asn_gt = asn_time2GT(NULL, localtime(&t_utc), true);
            CHECK_NOT_NULL(pkup->notBefore = asn_copy_with_alloc(&GeneralizedTime_desc, asn_gt));
            ASN_FREE(&GeneralizedTime_desc, asn_gt);
            asn_gt = NULL;
            break;

        case PKIXTime_PR_generalTime:
            CHECK_NOT_NULL(pkup->notBefore = asn_copy_with_alloc(&GeneralizedTime_desc, &validity->notBefore.choice.generalTime));
            break;

        default:
            LOG_ERROR();
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
        }

        switch (validity->notAfter.present) {
        case PKIXTime_PR_utcTime:
            t_utc = asn_UT2time(&validity->notAfter.choice.utcTime, NULL, false);
            asn_gt = asn_time2GT(NULL, localtime(&t_utc), true);
            pkup->notAfter = asn_copy_with_alloc(&GeneralizedTime_desc, asn_gt);
            ASN_FREE(&GeneralizedTime_desc, asn_gt);
            asn_gt = NULL;
            break;

        case PKIXTime_PR_generalTime:
            pkup->notAfter = asn_copy_with_alloc(&GeneralizedTime_desc, &validity->notAfter.choice.generalTime);
            break;

        default:
            LOG_ERROR();
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_TIME);
        }

    } else {

        pkup->notBefore = asn_time2GT(NULL, localtime(not_before), true);
        pkup->notAfter = asn_time2GT(NULL, localtime(not_after), true);
    }

    DO(type_to_octstring(&PrivateKeyUsagePeriod_desc, pkup, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&PrivateKeyUsagePeriod_desc, pkup);
    ASN_FREE(&GeneralizedTime_desc, asn_gt);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_qc_statement_compliance(QCStatement_t **out)
{
    QCStatement_t *qc_statement = NULL;
    int ret = RET_OK;

    CHECK_PARAM(out);

    ASN_ALLOC(qc_statement);
    DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_PKI_UKR_EDS_CP_ID)->numbers,
            oids_get_oid_numbers_by_id(OID_PKI_UKR_EDS_CP_ID)->numbers_len,
            &qc_statement->statementId));

    *out = qc_statement;
    qc_statement = NULL;

cleanup:

    ASN_FREE(&QCStatement_desc, qc_statement);

    return ret;
}

int ext_create_qc_statement_limit_value(const char *currency_code, long amount, long exponent, QCStatement_t **out)
{
    QCStatement_t *qc_statement = NULL;
    MonetaryValue_t *monetary_value = NULL;
    int ret = RET_OK;

    CHECK_PARAM(out);
    CHECK_PARAM(currency_code);
    CHECK_PARAM(strlen(currency_code) <= 3);

    ASN_ALLOC(monetary_value);
    DO(asn_long2INTEGER(&monetary_value->amount, amount));
    DO(asn_long2INTEGER(&monetary_value->exponent, exponent));
    monetary_value->currency.present = Iso4217CurrencyCode_PR_alphabetic;
    DO(asn_bytes2OCTSTRING(&monetary_value->currency.choice.alphabetic, (unsigned char *)currency_code,
            strlen(currency_code)));

    ASN_ALLOC(qc_statement);
    DO(asn_set_oid(oids_get_oid_numbers_by_id(OID_ETSI_QCS_QC_LIMIT_VALUE_ID)->numbers,
            oids_get_oid_numbers_by_id(OID_ETSI_QCS_QC_LIMIT_VALUE_ID)->numbers_len,
            &qc_statement->statementId));
    DO(asn_create_any(&MonetaryValue_desc, monetary_value, &qc_statement->statementInfo));

    *out = qc_statement;
    qc_statement = NULL;

cleanup:

    ASN_FREE(&QCStatement_desc, qc_statement);
    ASN_FREE(&MonetaryValue_desc, monetary_value);

    return ret;
}

int ext_create_qc_statements(bool critical, QCStatement_t **qc_statements, size_t qc_statements_len, Extension_t **out)
{
    int ret = RET_OK;
    QCStatements_t *qcss = NULL;
    QCStatement_t *qcs = NULL;
    Extension_t *ext = NULL;
    size_t i;

    LOG_ENTRY();

    CHECK_PARAM(qc_statements != NULL);
    CHECK_PARAM(qc_statements_len != 0);
    CHECK_PARAM(out != NULL);

    ASN_ALLOC(qcss);
    INIT_EXTENSION(&ext, OID_QC_STATEMENTS_EXTENSION_ID, critical);

    for (i = 0; i < qc_statements_len; ++i) {
        if (qc_statements[i] != NULL) {
            CHECK_NOT_NULL(qcs = asn_copy_with_alloc(&QCStatement_desc, qc_statements[i]));
            DO(ASN_SEQUENCE_ADD(&qcss->list, qcs));
            qcs = NULL;
        }
    }

    DO(type_to_octstring(&QCStatements_desc, qcss, &ext->extnValue));

    *out = ext;
    ext = NULL;

cleanup:

    ASN_FREE(&QCStatements_desc, qcss);
    ASN_FREE(&QCStatement_desc, qcs);
    ASN_FREE(&Extension_desc, ext);

    return ret;
}

int ext_create_subj_alt_name_directly(bool critical,
        enum GeneralName_PR types[],
        const char **names,
        int cnt,
        Extension_t **ext)
{
    int ret = RET_OK;
    SubjectAltName_t *san = NULL;
    GeneralName_t *gn = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(types != NULL);
    CHECK_PARAM(names != NULL);
    CHECK_PARAM(cnt != 0);

    ASN_ALLOC(san);
    INIT_EXTENSION(ext, OID_SUBJECT_ALT_NAME_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        switch (types[i]) {

        case GeneralName_PR_rfc822Name:
            ASN_ALLOC(gn);
            gn->present = types[i]; /* IA5String_t same as OCTET_STRING */
            DO(OCTET_STRING_fromString(&gn->choice.rfc822Name, names[i]));
            break;

        case GeneralName_PR_dNSName:
            ASN_ALLOC(gn);
            gn->present = types[i]; /* IA5String_t same as OCTET_STRING */
            DO(OCTET_STRING_fromString(&gn->choice.dNSName, names[i]));
            break;

        default:
            SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_OBJ);
        }

        DO(ASN_SEQUENCE_ADD(&san->list, gn));
        gn = NULL;
    }

    DO(type_to_octstring(&SubjectAltName_desc, san, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&SubjectAltName_desc, san);

    if (ret != RET_OK) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_subj_dir_attr_directly(bool critical, const char *subject_attr, Extension_t **ext)
{
    int ret = RET_OK;

    PrintableString_t *ps = NULL;
    SubjectDirectoryAttributes_t *sdas = NULL;
    Attribute_t *attr = NULL;
    AttributeValue_t *attrv = NULL;

    char **keys = NULL;
    char **values = NULL;
    size_t count = 0;
    long *oid_numbers = NULL;
    size_t oid_numbers_len = 0;
    size_t i;

    LOG_ENTRY();

    CHECK_PARAM(subject_attr != NULL);

    INIT_EXTENSION(ext, OID_SUBJECT_DIRECTORY_ATTRIBUTES_EXTENSION_ID, critical);

    DO(parse_key_value(subject_attr, &keys, &values, &count));

    ASN_ALLOC(sdas);

    for (i = 0; i < count; i++) {
        ASN_ALLOC(attr);
        ASN_ALLOC(ps);

        DO(asn_parse_args_oid(keys[i], &oid_numbers, &oid_numbers_len));
        DO(asn_set_oid(oid_numbers, oid_numbers_len, &attr->type));

        DO(OCTET_STRING_fromString(ps, values[i]));

        DO(asn_create_any(&PrintableString_desc, ps, &attrv));
        DO(ASN_SEQUENCE_ADD(&attr->value.list, attrv));

        DO(ASN_SEQUENCE_ADD(&sdas->list, attr));

        attrv = NULL;
        attr = NULL;

        ASN_FREE(&PrintableString_desc, ps);
        ps = NULL;
    }

    DO(type_to_octstring(&SubjectDirectoryAttributes_desc, sdas, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&PrintableString_desc, ps);
    ASN_FREE(&AttributeValue_desc, attrv);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&SubjectDirectoryAttributes_desc, sdas);

    while (keys && values && count--) {
        free(keys[count]);
        free(values[count]);
    }
    free(keys);
    free(values);
    free(oid_numbers);

    if (RET_OK != ret) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_subj_info_access(bool critical, OidNumbers **oids, const char **name_uris, int cnt, Extension_t **ext)
{
    int ret = RET_OK;
    SubjectInfoAccess_t *sia = NULL;
    AccessDescription_t *ad = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(oids != NULL);
    CHECK_PARAM(name_uris != NULL);
    CHECK_PARAM(cnt != 0);

    for (i = 0; i < cnt; ++i) {
        if (!oids[i]->numbers || !name_uris[i]) {
            LOG_ERROR();
            SET_ERROR(RET_INVALID_PARAM);
        }
    }

    ASN_ALLOC(sia);
    INIT_EXTENSION(ext, OID_SUBJECT_INFO_ACCESS_EXTENSION_ID, critical);

    for (i = 0; i < cnt; ++i) {
        ASN_ALLOC(ad);

        ad->accessLocation.present = GeneralName_PR_uniformResourceIdentifier;
        DO(OCTET_STRING_fromString(&ad->accessLocation.choice.uniformResourceIdentifier, name_uris[i]));
        EXT2OID(oids[i], ad->accessMethod);

        DO(ASN_SEQUENCE_ADD(&sia->list, ad));
        ad = NULL;
    }

    DO(type_to_octstring(&SubjectInfoAccess_desc, sia, &(*ext)->extnValue));

cleanup:

    ASN_FREE(&AccessDescription_desc, ad);
    ASN_FREE(&SubjectInfoAccess_desc, sia);

    if (RET_OK != ret) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_subj_key_id(bool critical,
        const SubjectPublicKeyInfo_t *spki,
        Extension_t **ext)
{
    int ret = RET_OK;

    SubjectKeyIdentifier_t *ski = NULL;
    ByteArray *key_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(ext != NULL);

    ASN_ALLOC(ski);
    INIT_EXTENSION(ext, OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID, critical);

    DO(pkix_get_key_id_from_spki(spki, &key_id));
    DO(asn_ba2OCTSTRING(key_id, ski));
    DO(type_to_octstring(&SubjectKeyIdentifier_desc, ski, &(*ext)->extnValue));

cleanup:

    ba_free(key_id);

    ASN_FREE(&SubjectKeyIdentifier_desc, ski);

    if (RET_OK != ret) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_create_nonce(bool critical, const ByteArray *rnd_bts, Extension_t **ext)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ext != NULL);
    CHECK_PARAM(rnd_bts != NULL);

    INIT_EXTENSION(ext, OID_NONCE_EXTENSION_ID, critical);
    DO(asn_ba2OCTSTRING(rnd_bts, &(*ext)->extnValue));

cleanup:

    if (RET_OK != ret) {
        ASN_FREE(&Extension_desc, *ext);
        *ext = NULL;
    }

    return ret;
}

int ext_get_value(const Extension_t *ext, ByteArray **value)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(ext != NULL);
    CHECK_PARAM(value != NULL);

    DO(asn_OCTSTRING2ba(&ext->extnValue, value));

cleanup:

    return ret;
}

void ext_free(Extension_t *ext)
{
    LOG_ENTRY();
    ASN_FREE(&Extension_desc, ext);
}
