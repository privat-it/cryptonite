/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "oids.h"
#include "signer_info.h"
#include "log_internal.h"
#include "pkix_utils.h"

#include "cert.h"
#include "pkix_macros_internal.h"


#undef FILE_MARKER
#define FILE_MARKER "pki/api/signer_info.c"

SignerInfo_t *sinfo_alloc(void)
{
    SignerInfo_t *sinfo = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(sinfo);

cleanup:

    return sinfo;
}

void sinfo_free(SignerInfo_t *sinfo)
{
    LOG_ENTRY();

    if (sinfo) {
        ASN_FREE(&SignerInfo_desc, sinfo);
    }
}

int sinfo_init(SignerInfo_t *sinfo,
        int version,
        const SignerIdentifier_t *signer_id,
        const DigestAlgorithmIdentifier_t *digest_aid,
        const Attributes_t *signed_attrs,
        const SignatureAlgorithmIdentifier_t *signed_aid,
        const OCTET_STRING_t *sign,
        const Attributes_t *unsigned_attrs)
{
    int ret = RET_OK;

    CMSVersion_t *version_copy = NULL;

    LOG_ENTRY();
    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(signer_id != NULL);
    CHECK_PARAM(digest_aid != NULL);
    CHECK_PARAM(signed_attrs != NULL);
    CHECK_PARAM(signed_aid != NULL);
    CHECK_PARAM(sign != NULL);

    ASN_FREE_CONTENT_PTR(&SignerInfo_desc, sinfo);

    DO(asn_create_integer_from_long(version, &version_copy));
    DO(asn_copy(&CMSVersion_desc, version_copy, &sinfo->version));
    DO(asn_copy(&SignerIdentifier_desc, signer_id, &sinfo->sid));
    DO(asn_copy(&DigestAlgorithmIdentifier_desc, digest_aid, &sinfo->digestAlgorithm));
    DO(asn_copy(&SignatureAlgorithmIdentifier_desc, signed_aid, &sinfo->signatureAlgorithm));
    CHECK_NOT_NULL(sinfo->signedAttrs = asn_copy_with_alloc(&Attributes_desc, signed_attrs));
    DO(asn_copy(&OCTET_STRING_desc, sign, &sinfo->signature));

    if (unsigned_attrs) {
        CHECK_NOT_NULL(sinfo->unsignedAttrs = asn_copy_with_alloc(&Attributes_desc, unsigned_attrs));
    }

cleanup:

    ASN_FREE(&CMSVersion_desc, version_copy);

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&SignerInfo_desc, sinfo);
    }

    return ret;
}

int sinfo_encode(const SignerInfo_t *sinfo, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&SignerInfo_desc, sinfo, out));
cleanup:
    return ret;
}

int sinfo_decode(SignerInfo_t *sinfo, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&SignerInfo_desc, sinfo);

    DO(asn_decode_ba(&SignerInfo_desc, sinfo, in));

cleanup:
    return ret;
}

int sinfo_get_version(const SignerInfo_t *sinfo, int *version)
{
    long val;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(version != NULL);

    DO(asn_INTEGER2long(&sinfo->version, &val));

    *version = (int)val;

cleanup:

    return ret;
}

int sinfo_get_signer_id(const SignerInfo_t *sinfo, SignerIdentifier_t **sid)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(sid != NULL);
    CHECK_PARAM(*sid == NULL);

    CHECK_NOT_NULL(*sid = asn_copy_with_alloc(&SignerIdentifier_desc, &sinfo->sid));

cleanup:

    return ret;
}

int sinfo_get_signed_attrs(const SignerInfo_t *sinfo, Attributes_t **attrs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attrs != NULL);
    CHECK_PARAM(*attrs == NULL);

    if (sinfo->signedAttrs == NULL ) {
        return RET_OK;
    }

    CHECK_NOT_NULL(*attrs = asn_copy_with_alloc(&Attributes_desc, sinfo->signedAttrs));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Attributes_desc, *attrs);
        *attrs = NULL;
    }
    return ret;
}

int sinfo_get_signed_attr_by_idx(const SignerInfo_t *sinfo, int index, Attribute_t **attr)
{
    int ret = RET_OK;
    Attributes_t *attrs = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attr != NULL);

    attrs = sinfo->signedAttrs;

    if (attrs == NULL ) {
        return RET_OK;
    }

    if (attrs->list.count < (index + 1)) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*attr = asn_copy_with_alloc(&Attribute_desc, attrs->list.array[index]));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Attribute_desc, *attr);
        *attr = NULL;
    }

    return ret;
}

int sinfo_get_signed_attr_by_oid(const SignerInfo_t *sinfo, const OBJECT_IDENTIFIER_t *oid, Attribute_t **attr)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attr != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(*attr == NULL);

    DO(get_attr_by_oid(sinfo->signedAttrs, oid, attr));

cleanup:

    return ret;
}

int sinfo_has_signed_attrs(const SignerInfo_t *sinfo, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (NULL != sinfo->signedAttrs);
cleanup:
    return ret;
}

int sinfo_get_unsigned_attrs(const SignerInfo_t *sinfo, Attributes_t **attrs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attrs != NULL);
    CHECK_PARAM(*attrs == NULL);

    if (sinfo->unsignedAttrs == NULL) {
        return RET_OK;
    }

    CHECK_NOT_NULL(*attrs = asn_copy_with_alloc(&Attributes_desc, sinfo->unsignedAttrs));

cleanup:

    return ret;
}

int sinfo_get_unsigned_attr_by_idx(const SignerInfo_t *sinfo, int index, Attribute_t **attr)
{
    int ret = RET_OK;
    Attributes_t *attrs = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attr != NULL);
    CHECK_PARAM(*attr == NULL);

    attrs = sinfo->unsignedAttrs;

    if (attrs == NULL) {
        return RET_OK;
    }

    if (attrs->list.count < (index + 1)) {
        SET_ERROR(RET_PKIX_OUT_OF_BOUND_ERROR);
    }

    CHECK_NOT_NULL(*attr = asn_copy_with_alloc(&Attribute_desc, attrs->list.array[index]));

cleanup:

    return ret;
}

int sinfo_get_unsigned_attr_by_oid(const SignerInfo_t *sinfo, const OBJECT_IDENTIFIER_t *oid, Attribute_t **attr)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attr != NULL);
    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(*attr == NULL);

    DO(get_attr_by_oid(sinfo->unsignedAttrs, oid, attr));

cleanup:

    return ret;
}

int sinfo_add_unsigned_attr(SignerInfo_t *sinfo, const Attribute_t *attr)
{
    int ret = RET_OK;
    Attribute_t *attr_copy = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(attr != NULL);

    if (sinfo->unsignedAttrs == NULL) {
        ASN_ALLOC(sinfo->unsignedAttrs);
    }

    CHECK_NOT_NULL(attr_copy = asn_copy_with_alloc(&Attribute_desc, attr));
    DO(asn_set_add(&sinfo->unsignedAttrs->list, attr_copy));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Attribute_desc, attr_copy);
    }

    return ret;
}

int sinfo_has_unsigned_attrs(const SignerInfo_t *sinfo, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (NULL != sinfo->unsignedAttrs);
cleanup:
    return ret;
}

int sinfo_verify_signing_cert_v2(const SignerInfo_t *sinfo,
        const DigestAdapter *adapter,
        const Certificate_t *issuer_cert)
{
    int ret = RET_OK;
    int i;

    OBJECT_IDENTIFIER_t *oid = NULL;
    Attribute_t *attr = NULL;
    SigningCertificateV2_t *signing_cert_v2 = NULL;
    DigestAlgorithmIdentifier_t *aid = NULL;
    ESSCertIDv2_t *ess_cert = NULL;
    ESSCertIDv2_t *esscert = NULL;

    ByteArray *digest = NULL;
    ByteArray *cert_hash = NULL;
    ByteArray *encoded = NULL;
    ByteArray *buffer = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(issuer_cert != NULL);
    CHECK_PARAM(adapter != NULL);

    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_AA_SIGNING_CERTIFICATE_V2_ID), &oid));
    ret = sinfo_get_signed_attr_by_oid(sinfo, oid, &attr);

    if (ret != RET_OK && ret != RET_PKIX_ATTRIBUTE_NOT_FOUND) {
        SET_ERROR(ret);
    }

    if (attr == NULL) {
        SET_ERROR(RET_PKIX_SDATA_NO_CERT_V2);
    }

    if (attr->value.list.count == 0) {
        SET_ERROR(RET_PKIX_SDATA_NO_CERT_V2);
    }

    if (attr->value.list.array[0] == NULL) {
        SET_ERROR(RET_PKIX_SDATA_NO_CERT_V2);
    }

    DO(asn_encode_ba(&AttributeValue_desc, (void *)attr->value.list.array[0], &buffer));
    CHECK_NOT_NULL(signing_cert_v2 = asn_decode_ba_with_alloc(&SigningCertificateV2_desc, buffer));

    for (i = 0; i < signing_cert_v2->certs.list.count; i++) {
        ess_cert = signing_cert_v2->certs.list.array[i];
        if (asn_equals(&CertificateSerialNumber_desc, &ess_cert->issuerSerial.serialNumber,
                &issuer_cert->tbsCertificate.serialNumber)) {
            CHECK_NOT_NULL(esscert = asn_copy_with_alloc(&ESSCertIDv2_desc, ess_cert));
            break;
        }
    }

    if (esscert == NULL) {
        SET_ERROR(RET_PKIX_SDATA_VERIFY_CERT_V2_FAILED);
    }


    CHECK_NOT_NULL(esscert);
    DO(adapter->get_alg(adapter, &aid));

    if (!asn_equals(&DigestAlgorithmIdentifier_desc, &esscert->hashAlgorithm, aid)) {
        SET_ERROR(RET_PKIX_DIFFERENT_DIGEST_ALG);
    }

    DO(cert_encode(issuer_cert, &encoded));
    DO(adapter->update(adapter, encoded));
    DO(adapter->final(adapter, &digest));
    DO(asn_OCTSTRING2ba(&esscert->certHash, &cert_hash));

    if (ba_cmp(digest, cert_hash)) {
        SET_ERROR(RET_PKIX_VERIFY_FAILED);
    }

cleanup:

    ba_free(encoded);
    ba_free(digest);
    ba_free(cert_hash);
    ba_free(buffer);

    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&SigningCertificateV2_desc, signing_cert_v2);
    ASN_FREE(&DigestAlgorithmIdentifier_desc, aid);
    ASN_FREE(&ESSCertIDv2_desc, esscert);

    return ret;
}

int verify_core_without_data(const SignerInfo_t *sinfo,
        const DigestAdapter *da,
        const VerifyAdapter *va)
{
    int ret = RET_OK;
    ByteArray *signed_attrs = NULL;
    ByteArray *sign = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);

    /*
     * Проверка: по результатам проверки цифровой подписи установлено, что
     * цифровая подпись верна;
     */
    /* IIT не сортирует атрибуты, потому их сортировка отключена, и при генерации выполняется принудительно !!! */
    DO(asn_encode_ba(&Attributes_desc, sinfo->signedAttrs, &signed_attrs));
    DO(sign_os_to_ba(&sinfo->signature, &sinfo->signatureAlgorithm, &sign));
    DO(va->verify_data(va, signed_attrs, sign));

cleanup:

    ba_free(sign);
    ba_free(signed_attrs);

    return ret;
}

int sinfo_get_message_digest(const SignerInfo_t *sinfo, ByteArray **hash)
{
    int ret = RET_OK;

    ByteArray *buffer = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    OCTET_STRING_t *hash_os = NULL;
    Attribute_t *message_digest_attr = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(hash != NULL);

    /*
     * Проверка: хэш-значение данных (инкапсулированных или внешних)
     * отвечает значению, приведенному в атрибуте “message-digest”.
     */
    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &message_digest_attr));

    if (message_digest_attr) {
        CHECK_NOT_NULL(message_digest_attr->value.list.array[0]);

        DO(asn_encode_ba(&AttributeValue_desc, (void *)message_digest_attr->value.list.array[0], &buffer));

        CHECK_NOT_NULL(hash_os = asn_decode_ba_with_alloc(&OCTET_STRING_desc, buffer));

        DO(asn_OCTSTRING2ba(hash_os, hash));
    }

cleanup:

    ba_free(buffer);

    ASN_FREE(&Attribute_desc, message_digest_attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&OCTET_STRING_desc, hash_os);

    return ret;
}

int verify_core(const SignerInfo_t *sinfo,
        const DigestAdapter *da,
        const VerifyAdapter *va,
        const ByteArray *data)
{
    int ret = RET_OK;
    uint8_t *buffer = NULL;
    size_t buffer_len;
    ByteArray *signed_attrs = NULL;

    OBJECT_IDENTIFIER_t *oid = NULL;
    Attribute_t *attr = NULL;
    OCTET_STRING_t *hash = NULL;

    ByteArray *digest = NULL;
    ByteArray *cert_hash = NULL;
    ByteArray *sign = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);
    CHECK_PARAM(data != NULL);

    /*
     * Проверка: хэш-значение данных (инкапсулированных или внешних)
     * отвечает значению, приведенному в атрибуте “message-digest”.
     */
    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID), &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

    CHECK_NOT_NULL(attr);
    CHECK_NOT_NULL(attr->value.list.array[0]);

    DO(asn_encode(&AttributeValue_desc, (void *)attr->value.list.array[0], &buffer, &buffer_len));
    CHECK_NOT_NULL(hash = asn_decode_with_alloc(&OCTET_STRING_desc, buffer, buffer_len));

    DO(asn_OCTSTRING2ba(hash, &cert_hash));
    DO(da->update(da, data));
    DO(da->final(da, &digest));

    if (ba_cmp(digest, cert_hash)) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_VERIFY_FAILED);
    }

    /*
     * Проверка: по результатам проверки цифровой подписи установлено, что
     * цифровая подпись верна;
     */
    /* IIT не сортирует атрибуты !!! */
    DO(asn_encode_ba(&Attributes_desc, sinfo->signedAttrs, &signed_attrs));
    DO(sign_os_to_ba(&sinfo->signature, &sinfo->signatureAlgorithm, &sign));
    DO(va->verify_data(va, signed_attrs, sign));
    LOG_ENTRY();

cleanup:

    ba_free(sign);
    ba_free(digest);
    ba_free(cert_hash);
    ba_free(signed_attrs);

    free(buffer);

    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OCTET_STRING_desc, hash);

    return ret;
}

int sinfo_verify_without_data(const SignerInfo_t *sinfo,
        const DigestAdapter *da,
        const VerifyAdapter *va)
{
    int ret = RET_OK;
    Certificate_t *issuer_cert = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);

    DO(va->get_cert(va, &issuer_cert));

    if (cert_check_sid(issuer_cert, &sinfo->sid)) {
        DO(verify_core_without_data(sinfo, da, va));
    } else {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER);
    }

cleanup:

    ASN_FREE(&Certificate_desc, issuer_cert);

    return ret;
}

int sinfo_verify(const SignerInfo_t *sinfo,
        const DigestAdapter *da,
        const VerifyAdapter *va,
        const ByteArray *data)
{
    int ret = RET_OK;
    Certificate_t *issuer_cert = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(da != NULL);
    CHECK_PARAM(va != NULL);
    CHECK_PARAM(data != NULL);

    DO(va->get_cert(va, &issuer_cert));

    if (cert_check_sid(issuer_cert, &sinfo->sid)) {
        DO(verify_core(sinfo, da, va, data));
    } else {
        SET_ERROR(RET_PKIX_DIFFERENT_SIGNER_IDENTIFIER);
    }

cleanup:

    ASN_FREE(&Certificate_desc, issuer_cert);

    return ret;
}

/**
 * Проверяет наличие неподписываемого атрибута по OID`у.
 *
 * @param sinfo информация о подписчике
 * @param oid_longs идентификатор
 *
 * @return код ошибки
 */
static int check_unsigned_attr(const SignerInfo_t *sinfo, const OidNumbers *oid_longs)
{
    int ret = RET_OK;
    Attribute_t *attr = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;

    LOG_ENTRY();

    DO(pkix_create_oid(oid_longs, &oid));
    DO(sinfo_get_unsigned_attr_by_oid(sinfo, oid, &attr));

cleanup:

    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);

    return ret;
}

/**
 * Проверяет наличие подписываемого атрибута по OID`у.
 *
 * @param sinfo информация о подписчике
 * @param oid_arr идентификатор
 *
 * @return код ошибки
 */
static int check_signed_attr(const SignerInfo_t *sinfo, const OidNumbers *oid_arr)
{
    int ret = RET_OK;
    Attribute_t *attr = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;

    LOG_ENTRY();

    DO(pkix_create_oid(oid_arr, &oid));
    DO(sinfo_get_signed_attr_by_oid(sinfo, oid, &attr));

cleanup:

    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);

    return ret;
}

int sinfo_get_format(const SignerInfo_t *sinfo, int *format)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sinfo != NULL);
    CHECK_PARAM(format != NULL);

    *format = 0;

    if (sinfo->signedAttrs == NULL) {
        return RET_OK;
    }

    ret = check_signed_attr(sinfo, oids_get_oid_numbers_by_id(OID_CONTENT_TYPE_ID));
    if (ret == RET_PKIX_ATTRIBUTE_NOT_FOUND) {
        return RET_OK;
    } else if (ret != RET_OK) {
        return ret;
    }

    ret = check_signed_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_SIGNING_CERTIFICATE_V2_ID));
    if (ret == RET_PKIX_ATTRIBUTE_NOT_FOUND) {
        return RET_OK;
    } else if (ret != RET_OK) {
        return ret;
    }

    ret = check_signed_attr(sinfo, oids_get_oid_numbers_by_id(OID_MESSAGE_DIGEST_ID));
    if (ret == RET_PKIX_ATTRIBUTE_NOT_FOUND) {
        return RET_OK;
    } else if (ret != RET_OK) {
        return ret;
    }

    *format |= CADES_BES_FORMAT;

    ret = check_signed_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_ETS_SIG_POLICY_ID));
    if (ret == RET_OK) {
        *format |= CADES_EPES_FORMAT;
    }

    ret = check_unsigned_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_ETS_CERTIFICATE_REFS_ID));
    ret |= check_unsigned_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_ETS_REVOCATION_REFS_ID));
    ret |= check_unsigned_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_SIGNATURE_TIME_STAMP_TOKEN_ID));
    if (ret == RET_OK) {
        *format |= CADES_C_FORMAT;
    }

    ret = check_unsigned_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_ETS_CERT_VALUES_ID));
    ret |= check_unsigned_attr(sinfo, oids_get_oid_numbers_by_id(OID_AA_ETS_REVOCATION_VALUES_ID));

    if (ret == RET_OK) {
        *format |= CADES_X_FORMAT;
    }
    ret = RET_OK;

cleanup:

    return ret;
}
