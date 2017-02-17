/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "SignerInfos.h"
#include "DigestAlgorithmIdentifiers.h"
#include "asn1_utils.h"
#include "oids.h"
#include "cryptonite_manager.h"
#include "signed_data.h"
#include "log_internal.h"
#include "pkix_utils.h"
#include "signer_info.h"
#include "content_info.h"
#include "signed_data.h"
#include "cert.h"
#include "pkix_macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/signed_data.c"

SignedData_t *sdata_alloc(void)
{
    SignedData_t *sdata = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(sdata);

cleanup:

    return sdata;
}

void sdata_free(SignedData_t *sdata)
{
    LOG_ENTRY();

    if (sdata) {
        ASN_FREE(&SignedData_desc, sdata);
    }
}

int sdata_init(SignedData_t *sdata,
        int version,
        const DigestAlgorithmIdentifiers_t *digest_aid,
        const EncapsulatedContentInfo_t *content,
        const SignerInfos_t *signer)
{
    int ret = RET_OK;
    CMSVersion_t *version_copy = NULL;

    LOG_ENTRY();


    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(digest_aid != NULL);
    CHECK_PARAM(content != NULL);
    CHECK_PARAM(signer != NULL);

    version_copy = &sdata->version;
    DO(asn_create_integer_from_long(version, &version_copy));

    DO(asn_copy(&AlgorithmIdentifiers_desc, digest_aid, &sdata->digestAlgorithms));
    DO(asn_copy(&EncapsulatedContentInfo_desc, content, &sdata->encapContentInfo));
    DO(asn_copy(&SignerInfos_desc, signer, &sdata->signerInfos));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&SignedData_desc, sdata);
    }

    return ret;
}

int sdata_encode(const SignedData_t *sdata, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(out != NULL);
    CHECK_PARAM(*out == NULL);

    DO(asn_encode_ba(&SignedData_desc, sdata, out));
cleanup:
    return ret;
}

int sdata_decode(SignedData_t *sdata, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&SignedData_desc, sdata);

    DO(asn_decode_ba(&SignedData_desc, sdata, in));

cleanup:

    return ret;
}

int sdata_get_version(const SignedData_t *sdata, int *version)
{
    long val;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(version != NULL);

    DO(asn_INTEGER2long(&sdata->version, &val));

    *version = (int)val;
cleanup:
    return ret;
}

int sdata_set_version(SignedData_t *sdata, int version)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);

    DO(asn_long2INTEGER(&sdata->version, version));

cleanup:

    return ret;
}

int sdata_get_digest_aids(const SignedData_t *sdata, DigestAlgorithmIdentifiers_t **digest_aids)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(digest_aids != NULL);
    CHECK_PARAM(*digest_aids == NULL);

    CHECK_NOT_NULL(*digest_aids = asn_copy_with_alloc(&DigestAlgorithmIdentifiers_desc, &sdata->digestAlgorithms));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&DigestAlgorithmIdentifiers_desc, *digest_aids);
        *digest_aids = NULL;
    }

    return ret;
}

int sdata_set_digest_aids(SignedData_t *sdata, const DigestAlgorithmIdentifiers_t *digest_aids)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(digest_aids != NULL);

    ASN_FREE_CONTENT_STATIC(&DigestAlgorithmIdentifiers_desc, &sdata->digestAlgorithms);

    DO(asn_copy(&DigestAlgorithmIdentifiers_desc, digest_aids, &sdata->digestAlgorithms));

cleanup:

    return ret;
}

int sdata_get_digest_aid_by_idx(const SignedData_t *sdata, int index, AlgorithmIdentifier_t **digest_aid)
{
    int ret = RET_OK;
    DigestAlgorithmIdentifiers_t digest_aids;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(digest_aid != NULL);
    CHECK_PARAM(*digest_aid == NULL);

    digest_aids = sdata->digestAlgorithms;

    if (digest_aids.list.count < index) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*digest_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc, digest_aids.list.array[index]));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&AlgorithmIdentifier_desc, *digest_aid);
        *digest_aid = NULL;
    }

    return ret;
}

int sdata_get_content(const SignedData_t *sdata, EncapsulatedContentInfo_t **content)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(content != NULL);

    CHECK_NOT_NULL(*content = asn_copy_with_alloc(&EncapsulatedContentInfo_desc, &sdata->encapContentInfo));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&EncapsulatedContentInfo_desc, *content);
        *content = NULL;
    }

    return ret;
}

int sdata_get_data(const SignedData_t *sdata, ByteArray **data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(data != NULL);

    if (!pkix_check_oid_equal(&sdata->encapContentInfo.eContentType, oids_get_oid_numbers_by_id(OID_DATA_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_SDATA_CONTENT_NOT_DATA);
    }

    if (sdata->encapContentInfo.eContent) {
        DO(asn_OCTSTRING2ba(sdata->encapContentInfo.eContent, data));
    }

cleanup:

    return ret;
}

int sdata_get_tst_info(const SignedData_t *sdata, TSTInfo_t **info)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(info != NULL);

    if (!pkix_check_oid_equal(&sdata->encapContentInfo.eContentType, oids_get_oid_numbers_by_id(OID_CT_TST_INFO_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_SDATA_CONTENT_NOT_TST_INFO);
    }

    if (sdata->encapContentInfo.eContent) {
        CHECK_NOT_NULL(*info = asn_decode_with_alloc(&TSTInfo_desc, sdata->encapContentInfo.eContent->buf,
                sdata->encapContentInfo.eContent->size));
    }

cleanup:

    return ret;
}

int sdata_set_content(SignedData_t *sdata, const EncapsulatedContentInfo_t *content)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(content != NULL);

    ASN_FREE_CONTENT_STATIC(&EncapsulatedContentInfo_desc, &sdata->encapContentInfo);

    DO(asn_copy(&EncapsulatedContentInfo_desc, content, &sdata->encapContentInfo));

cleanup:

    return ret;
}

int sdata_get_certs(const SignedData_t *sdata, CertificateSet_t **certs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(certs != NULL);
    CHECK_PARAM(*certs == NULL);

    if (!sdata->certificates) {
        LOG_ENTRY();
        return RET_OK;
    }

    CHECK_NOT_NULL(*certs = asn_copy_with_alloc(&CertificateSet_desc, sdata->certificates));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&CertificateSet_desc, *certs);
        *certs = NULL;
    }

    return ret;
}

int sdata_set_certs(SignedData_t *sdata, const CertificateSet_t *certs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);

    if (certs == NULL) {
        sdata->certificates = NULL;
        return RET_OK;
    }

    ASN_FREE(&CertificateSet_desc, sdata->certificates);
    CHECK_NOT_NULL(sdata->certificates = asn_copy_with_alloc(&CertificateSet_desc, certs));

cleanup:

    return ret;
}

int sdata_has_certs(const SignedData_t *sdata, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (NULL != sdata->certificates);
cleanup:
    return ret;
}

int sdata_get_crls(const SignedData_t *sdata, RevocationInfoChoices_t **crls)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(crls != NULL);
    CHECK_PARAM(*crls == NULL);

    if (sdata->crls == NULL ) {
        return RET_OK;
    }

    CHECK_NOT_NULL(*crls = asn_copy_with_alloc(&RevocationInfoChoices_desc, sdata->crls));

cleanup:

    return ret;
}

int sdata_set_crls(SignedData_t *sdata, const RevocationInfoChoices_t *crls)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(crls != NULL);

    ASN_FREE(&RevocationInfoChoices_desc, sdata->crls);
    CHECK_NOT_NULL(sdata->crls = asn_copy_with_alloc(&RevocationInfoChoices_desc, crls));

cleanup:

    return ret;
}

int sdata_has_crls(const SignedData_t *sdata, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (NULL != sdata->crls);
cleanup:
    return ret;
}

int sdata_get_signer_infos(const SignedData_t *sdata, SignerInfos_t **sinfos)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(sinfos != NULL);
    CHECK_PARAM(*sinfos == NULL);

    CHECK_NOT_NULL(*sinfos = asn_copy_with_alloc(&SignerInfos_desc, &sdata->signerInfos));

cleanup:

    return ret;
}

int sdata_set_signer_infos(SignedData_t *sdata, const SignerInfos_t *sinfos)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(sinfos != NULL);

    ASN_FREE_CONTENT_STATIC(&SignerInfos_desc, &sdata->signerInfos);

    DO(asn_copy(&SignerInfos_desc, sinfos, &sdata->signerInfos));

cleanup:

    return ret;
}

int sdata_get_cert_by_idx(const SignedData_t *sdata, int index, CertificateChoices_t **cert)
{
    int ret = RET_OK;
    CertificateSet_t *clist = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(*cert == NULL);

    clist = sdata->certificates;

    if (clist == NULL || clist->list.count < (index + 1)) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&CertificateChoices_desc, clist->list.array[index]));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&CertificateChoices_desc, *cert);
        *cert = NULL;
    }

    return ret;
}

int sdata_get_crl_by_idx(const SignedData_t *sdata, int index, RevocationInfoChoice_t **crl)
{
    int ret = RET_OK;
    RevocationInfoChoices_t *crls = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(crl != NULL);
    CHECK_PARAM(*crl == NULL);

    crls = sdata->crls;

    if (crls == NULL || crls->list.count < (index + 1)) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*crl = asn_copy_with_alloc(&RevocationInfoChoice_desc, crls->list.array[index]));

cleanup:

    return ret;
}

int sdata_get_signer_info_by_idx(const SignedData_t *sdata, int index, SignerInfo_t **sinfo)
{
    int ret = RET_OK;
    SignerInfos_t sinfos;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(*sinfo == NULL);

    sinfos = sdata->signerInfos;

    if (sinfos.list.count < (index + 1)) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*sinfo = asn_copy_with_alloc(&SignerInfo_desc, sinfos.list.array[index]));

cleanup:

    return ret;
}

int sdata_verify_without_data_by_adapter(const SignedData_t *sdata,
        const DigestAdapter *da,
        const VerifyAdapter *va,
        int index)
{
    int ret = RET_OK;

    SignerInfo_t *sinfo = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    OBJECT_IDENTIFIER_t *content_oid = NULL;
    Attribute_t *attr = NULL;

    uint8_t *buffer = NULL;
    size_t buffer_len;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);

    if (sdata->signerInfos.list.count < (index + 1)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    sinfo = sdata->signerInfos.list.array[index];

    /**
     * Проверяем совпадение атрибута "content-type" с "eContentType" структуры
     * "encapContentInfo" в "signed-data".
     */
    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_CONTENT_TYPE_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

    DO(asn_encode(&AttributeValue_desc, (void *)attr->value.list.array[0], &buffer, &buffer_len));
    CHECK_NOT_NULL(content_oid = asn_decode_with_alloc(&OBJECT_IDENTIFIER_desc, buffer, buffer_len));

    if (!asn_equals(&OBJECT_IDENTIFIER_desc, &sdata->encapContentInfo.eContentType, content_oid)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_VERIFY_FAILED);
    }

    DO(sinfo_verify_without_data(sinfo, da, va));

cleanup:

    free(buffer);

    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, content_oid);

    return ret;
}

int sdata_get_content_time_stamp(const SignedData_t *sdata, int index, TspStatus *status, time_t *content_time_stamp,
        SignerIdentifier_t **signer_identifier)
{
    int ret = RET_OK;

    const SignerInfo_t *sinfo;
    OBJECT_IDENTIFIER_t *oid = NULL;
    Attribute_t *attr = NULL;
    ContentInfo_t *tsp_cinfo = NULL;
    SignedData_t *tsp_sdata = NULL;
    EncapsulatedContentInfo_t *tsp_content = NULL;
    TSTInfo_t *tst_info = NULL;

    ByteArray *buffer = NULL;

    DigestAdapter *da = NULL;
    VerifyAdapter *va = NULL;
    CertificateSet_t *certs_set = NULL;
    Certificate_t *tsp_cert = NULL;

    DigestAdapter *da_messageImprint = NULL;
    ByteArray *hash_data_act = NULL;
    ByteArray *hash_data_exp = NULL;

    SignerIdentifier_t *signer = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);

    if (sdata->signerInfos.list.count < (index + 1) || index < 0) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    sinfo = sdata->signerInfos.list.array[index];

    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_AA_ETS_CONTENT_TIME_STAMP_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

    DO(asn_encode_ba(&AttributeValue_desc, (void *)attr->value.list.array[0], &buffer));
    CHECK_NOT_NULL(tsp_cinfo = asn_decode_ba_with_alloc(&ContentInfo_desc, buffer));

    DO(cinfo_get_signed_data(tsp_cinfo, &tsp_sdata));

    DO(sdata_get_certs(tsp_sdata, &certs_set));

    if (tsp_sdata->signerInfos.list.count > 0) {
        int usage_signature = 1 << KeyUsage_digitalSignature;
        ret = get_cert_by_sid_and_usage(&tsp_sdata->signerInfos.list.array[0]->sid, usage_signature, certs_set, &tsp_cert);
        /* if ret != RET_OK - TSP сертификат не найде. */
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_SDATA_NO_SIGNERS);
    }

    if (sdata_get_tst_info(tsp_sdata, &tst_info) != RET_OK) {
        DO(RET_PKIX_WRONG_TSP_DATA);
    }

    *content_time_stamp = asn_GT2time(&tst_info->genTime, NULL, false);

    CHECK_NOT_NULL(signer = asn_copy_with_alloc(&SignerIdentifier_desc, &tsp_sdata->signerInfos.list.array[0]->sid));

    /* Проверяем, что метка времени от нужных данных. */
    DO(asn_OCTSTRING2ba(&tst_info->messageImprint.hashedMessage, &hash_data_act));
    DO(sinfo_get_message_digest(sinfo, &hash_data_exp));

    if (ba_cmp(hash_data_act, hash_data_exp)) {
        LOG_ERROR();
        LOG_BYTES(LOG_ALWAYS, "hash_data_act", hash_data_act, hash_data_act_len);
        LOG_BYTES(LOG_ALWAYS, "hash_data_exp", hash_data_exp, hash_data_exp_len);
        *status = TSP_INVALID_DATA;
    } else {
        if (tsp_cert != NULL) {
            DO(digest_adapter_init_default(&da));
            DO(verify_adapter_init_by_cert(tsp_cert, &va));
            if (sdata_verify_internal_data_by_adapter(tsp_sdata, da, va, 0) == RET_OK) {
                LOG_ENTRY();
                *status = TSP_VALID;
            } else {
                LOG_ERROR();
                *status = TSP_INVALID;
            }
        } else {
            LOG_ERROR();
            *status = TSP_NO_CERT_FOR_VERIFY;
        }
    }

    *signer_identifier = signer;
    signer = NULL;

cleanup:

    ba_free(buffer);
    ba_free(hash_data_act);
    ba_free(hash_data_exp);

    verify_adapter_free(va);
    digest_adapter_free(da);
    digest_adapter_free(da_messageImprint);

    cert_free(tsp_cert);

    ASN_FREE(&CertificateSet_desc, certs_set);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&ContentInfo_desc, tsp_cinfo);
    ASN_FREE(&SignedData_desc, tsp_sdata);
    ASN_FREE(&EncapsulatedContentInfo_desc, tsp_content);
    ASN_FREE(&TSTInfo_desc, tst_info);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&SignerIdentifier_desc, signer);

    return ret;
}

int sdata_get_signing_time(const SignedData_t *sdata, int index, time_t *signing_time)
{
    int ret = RET_OK;

    SignerInfo_t *sinfo = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    UTCTime_t *signing_time_asn1 = NULL;
    Attribute_t *attr = NULL;

    uint8_t *buffer = NULL;
    size_t buffer_len;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);

    if (sdata->signerInfos.list.count < (index + 1)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    sinfo = sdata->signerInfos.list.array[index];

    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_SIGNING_TIME_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

    DO(asn_encode(&AttributeValue_desc, (void *)attr->value.list.array[0], &buffer, &buffer_len));
    CHECK_NOT_NULL(signing_time_asn1 = asn_decode_with_alloc(&UTCTime_desc, buffer, buffer_len));

    *signing_time = asn_UT2time(signing_time_asn1, NULL, false);

cleanup:

    free(buffer);

    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&UTCTime_desc, signing_time_asn1);

    return ret;
}

int sdata_verify_external_data_by_adapter(const SignedData_t *sdata, const DigestAdapter *da, const VerifyAdapter *va,
        const ByteArray *data, int index)
{
    int ret = RET_OK;

    const SignerInfo_t *sinfo;
    OBJECT_IDENTIFIER_t *oid = NULL;
    OBJECT_IDENTIFIER_t *content_oid = NULL;
    Attribute_t *attr = NULL;

    ByteArray *buffer = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);
    CHECK_PARAM(data != NULL);

    if (sdata->signerInfos.list.count < (index + 1)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    sinfo = sdata->signerInfos.list.array[index];

    /**
     * Проверяем совпадение атрибута "content-type" с "eContentType" структуры
     * "encapContentInfo" в "signed-data".
     */
    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_CONTENT_TYPE_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

    DO(asn_encode_ba(&AttributeValue_desc, attr->value.list.array[0], &buffer));

    CHECK_NOT_NULL(content_oid = asn_decode_ba_with_alloc(&OBJECT_IDENTIFIER_desc, buffer));
    if (!asn_equals(&OBJECT_IDENTIFIER_desc, &sdata->encapContentInfo.eContentType, content_oid)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_VERIFY_FAILED);
    }

    DO(sinfo_verify(sinfo, da, va, data));

cleanup:

    ba_free(buffer);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, content_oid);

    return ret;
}

int sdata_verify_internal_data_by_adapter(const SignedData_t *sdata, const DigestAdapter *da, const VerifyAdapter *va,
        int index)
{
    int ret = RET_OK;
    ByteArray *buffer = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);

    if (sdata->signerInfos.list.count < (index + 1)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    if (sdata->encapContentInfo.eContent == NULL) {
        SET_ERROR(RET_PKIX_SDATA_NO_CONTENT);
    }

    DO(asn_OCTSTRING2ba(sdata->encapContentInfo.eContent, &buffer));
    CHECK_NOT_NULL(buffer);

    DO(sdata_verify_external_data_by_adapter(sdata, da, va, buffer, index));

cleanup:

    ba_free(buffer);

    return ret;
}

int sdata_verify_signing_cert_by_adapter(const SignedData_t *sdata, const DigestAdapter *da, const Certificate_t *cert,
        int index)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sdata != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(cert != NULL);

    if (sdata->signerInfos.list.count == 0) {
        SET_ERROR(RET_PKIX_SDATA_NO_SIGNERS);
    }

    if (sdata->signerInfos.list.count < (index + 1)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    DO(sinfo_verify_signing_cert_v2(sdata->signerInfos.list.array[index], da, cert));

cleanup:

    return ret;
}
