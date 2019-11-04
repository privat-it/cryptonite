/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "enveloped_data.h"

#include <stdlib.h>

#include "asn1_utils.h"
#include "oids.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "pkix_utils.h"
#include "exts.h"
#include "cert.h"
#include "cryptonite_manager.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/enveloped_data.c"
/**
 * Проверяет соотвествие серийного номера и имени сертификату.
 *
 * @param issuer_serial серийный номер и имя
 * @param issuer_cert   сертификат
 *
 * @return код ошибки
 */
static bool equals_issuer_and_sn(const IssuerAndSerialNumber_t *issuer_sn, const Certificate_t *issuer_cert)
{
    return (asn_equals(&CertificateSerialNumber_desc,
            &issuer_sn->serialNumber,
            &issuer_cert->tbsCertificate.serialNumber)
            && asn_equals(&Name_desc, &issuer_sn->issuer, &issuer_cert->tbsCertificate.issuer));
}

EnvelopedData_t *env_data_alloc(void)
{
    EnvelopedData_t *env_data = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(env_data);

cleanup:

    return env_data;
}

void env_data_free(EnvelopedData_t *env_data)
{
    LOG_ENTRY();
    ASN_FREE(&EnvelopedData_desc, env_data);
}

int env_data_init(EnvelopedData_t *env_data,
        const CMSVersion_t *version,
        const OriginatorInfo_t *originator,
        const RecipientInfos_t *recipient,
        const EncryptedContentInfo_t *content,
        const UnprotectedAttributes_t *attrs)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(recipient != NULL);
    CHECK_PARAM(content != NULL);

    ASN_FREE_CONTENT_PTR(&EnvelopedData_desc, env_data);

    DO(asn_copy(&CMSVersion_desc, version, &env_data->version));
    DO(asn_copy(&RecipientInfos_desc, recipient, &env_data->recipientInfos));
    DO(asn_copy(&EncryptedContentInfo_desc, content, &env_data->encryptedContentInfo));

    if (attrs) {
        CHECK_NOT_NULL(env_data->unprotectedAttrs = asn_copy_with_alloc(&UnprotectedAttributes_desc, attrs));
    }

    if (originator) {
        CHECK_NOT_NULL(env_data->originatorInfo = asn_copy_with_alloc(&OriginatorInfo_desc, originator));
    }

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&EnvelopedData_desc, env_data);
    }

    return ret;
}

int env_data_encode(const EnvelopedData_t *env_data, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&EnvelopedData_desc, env_data, out));
cleanup:
    return ret;
}

int env_data_decode(EnvelopedData_t *env_data, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&EncryptedData_desc, env_data);

    DO(asn_decode_ba(&EnvelopedData_desc, env_data, in));

cleanup:
    return ret;
}

int env_data_has_originator_cert(const EnvelopedData_t *env_data, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (env_data->originatorInfo != NULL) && (env_data->originatorInfo->certs->list.count > 0);
cleanup:
    return ret;
}

int env_data_get_originator_cert(const EnvelopedData_t *env_data, Certificate_t **originator_cert)
{
    int ret = RET_OK;
    int index = 0;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(originator_cert != NULL);
    CHECK_PARAM(*originator_cert == NULL);

    if (!env_data->originatorInfo) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }

    index = env_data->originatorInfo->certs->list.count - 1;
    CHECK_NOT_NULL(*originator_cert = asn_copy_with_alloc(&Certificate_desc,
            &env_data->originatorInfo->certs->list.array[index]->choice.certificate));

cleanup:

    return ret;
}

static int kari_get_originator_public_key(const KeyAgreeRecipientInfo_t *kari, const Certificate_t *originator_cert_opt,
        ByteArray **pub_key)
{
    int ret = RET_OK;

    const BIT_STRING_t *pub_key_ptr = NULL;
    const OBJECT_IDENTIFIER_t *oid = NULL;
    ByteArray *cert_subj_key_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(kari != NULL);
    CHECK_PARAM(pub_key != NULL);

    if (kari->originator.present == OriginatorIdentifierOrKey_PR_originatorKey) {
        pub_key_ptr = &kari->originator.choice.originatorKey.publicKey;
        CHECK_NOT_NULL(oid = &kari->originator.choice.originatorKey.algorithm.algorithm);

    } else if (kari->originator.present == OriginatorIdentifierOrKey_PR_issuerAndSerialNumber) {
        if (!originator_cert_opt) {
            SET_ERROR(RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT);
        }

        if (equals_issuer_and_sn(&kari->originator.choice.issuerAndSerialNumber, originator_cert_opt)) {
            pub_key_ptr = &originator_cert_opt->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
            oid = &originator_cert_opt->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
        } else {
            SET_ERROR(RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT);
        }

    } else if (kari->originator.present == OriginatorIdentifierOrKey_PR_subjectKeyIdentifier) {
        if (!originator_cert_opt) {
            SET_ERROR(RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT);
        }

        DO(cert_get_subj_key_id(originator_cert_opt, &cert_subj_key_id));
        if (kari->originator.choice.subjectKeyIdentifier.size == (int)ba_get_len(cert_subj_key_id)
                && memcmp(kari->originator.choice.subjectKeyIdentifier.buf, ba_get_buf(cert_subj_key_id),
                        kari->originator.choice.subjectKeyIdentifier.size) == 0) {
            pub_key_ptr = &originator_cert_opt->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
            oid = &originator_cert_opt->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
        } else {
            SET_ERROR(RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT);
        }
    }

    DO(convert_pub_key_bs_to_ba(oid, pub_key_ptr, pub_key));

cleanup:

    ba_free(cert_subj_key_id);

    return ret;
}

int env_data_get_originator_public_key(const EnvelopedData_t *env_data, const Certificate_t *originator_cert,
        ByteArray **originator_pub_key)
{
    int ret = RET_OK;
    int i;

    const KeyAgreeRecipientInfo_t *kari = NULL;
    const BIT_STRING_t *pub_key_ptr = NULL;
    const OBJECT_IDENTIFIER_t *oid = NULL;
    ByteArray *cert_subj_key_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(originator_pub_key != NULL);

    for (i = 0; i < env_data->recipientInfos.list.count; i++) {

        kari = &env_data->recipientInfos.list.array[i]->choice.kari;

        if (kari->originator.present == OriginatorIdentifierOrKey_PR_originatorKey) {
            pub_key_ptr = &kari->originator.choice.originatorKey.publicKey;
            CHECK_NOT_NULL(oid = &kari->originator.choice.originatorKey.algorithm.algorithm);
            break;

        } else if (kari->originator.present == OriginatorIdentifierOrKey_PR_issuerAndSerialNumber) {
            if (!originator_cert) {
                continue;
            }

            if (equals_issuer_and_sn(&kari->originator.choice.issuerAndSerialNumber, originator_cert)) {
                pub_key_ptr = &originator_cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
                oid = &originator_cert->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
                break;
            }

        } else if (kari->originator.present == OriginatorIdentifierOrKey_PR_subjectKeyIdentifier) {
            if (!originator_cert) {
                continue;
            }

            DO(cert_get_subj_key_id(originator_cert, &cert_subj_key_id));
            if (kari->originator.choice.subjectKeyIdentifier.size == (int)ba_get_len(cert_subj_key_id)
                    && memcmp(kari->originator.choice.subjectKeyIdentifier.buf, ba_get_buf(cert_subj_key_id),
                            kari->originator.choice.subjectKeyIdentifier.size) == 0) {
                pub_key_ptr = &originator_cert->tbsCertificate.subjectPublicKeyInfo.subjectPublicKey;
                oid = &originator_cert->tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
                break;
            }
        }
    }

    if (pub_key_ptr) {
        DO(convert_pub_key_bs_to_ba(oid, pub_key_ptr, originator_pub_key));
    } else {
        SET_ERROR(RET_PKIX_RECIPIENT_NOT_FOUND);
    }

cleanup:

    ba_free(cert_subj_key_id);

    return ret;
}

static int env_get_info_for_unwrap(const EnvelopedData_t *env_data, const Certificate_t *originator_cert_opt,
        const Certificate_t *recipient_cert, ByteArray **encrypted_session_key, ByteArray **rnd_bytes,
        ByteArray **originator_pub_key)
{
    int ret = RET_OK;

    int i, j;
    KeyAgreeRecipientInfo_t *kari = NULL;
    RecipientEncryptedKeys_t *keys = NULL;
    RecipientEncryptedKey_t *rekey = NULL;
    ByteArray *subj_key_id_ext = NULL;
    OCTET_STRING_t *subjectKeyIdentifier = NULL;
    ByteArray *encrypted_session_key_ptr = NULL;
    ByteArray *rnd_bytes_ptr = NULL;
    ByteArray *originator_pub_key_ptr = NULL;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(recipient_cert != NULL);
    CHECK_PARAM(encrypted_session_key != NULL);

    for (i = 0; i < env_data->recipientInfos.list.count; i++) {

        kari = &env_data->recipientInfos.list.array[i]->choice.kari;
        keys = &kari->recipientEncryptedKeys;

        for (j = 0; j < keys->list.count; j++) {

            rekey = keys->list.array[j];

            switch (rekey->rid.present) {
            case KeyAgreeRecipientIdentifier_PR_issuerAndSerialNumber:
                if (equals_issuer_and_sn(&rekey->rid.choice.issuerAndSerialNumber, recipient_cert)) {
                    goto recipient_found;
                }
                break;

            case KeyAgreeRecipientIdentifier_PR_rKeyId:
                if (subj_key_id_ext == NULL) {
                    DO(exts_get_ext_value_by_oid(recipient_cert->tbsCertificate.extensions,
                            oids_get_oid_numbers_by_id(OID_SUBJECT_KEY_IDENTIFIER_EXTENSION_ID),
                            &subj_key_id_ext));
                    CHECK_NOT_NULL(subjectKeyIdentifier = asn_decode_ba_with_alloc(&OCTET_STRING_desc, subj_key_id_ext));
                }

                if (asn_equals(&OCTET_STRING_desc, subjectKeyIdentifier, &rekey->rid.choice.rKeyId.subjectKeyIdentifier)) {
                    goto recipient_found;
                }

                break;

            default:
                LOG_ERROR();
                SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_OBJ);
            }
        }
    }

    SET_ERROR(RET_PKIX_RECIPIENT_NOT_FOUND);
    LOG_ERROR_CODE(ret);

recipient_found:

    DO(asn_OCTSTRING2ba(&rekey->encryptedKey, &encrypted_session_key_ptr));
    if (kari->ukm != NULL) {
        DO(asn_OCTSTRING2ba(kari->ukm, &rnd_bytes_ptr));
    }
    ret = kari_get_originator_public_key(kari, originator_cert_opt, &originator_pub_key_ptr);
    if (ret != RET_OK && ret != RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT && ret != RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT) {
        SET_ERROR(ret);
    }

    if (env_data->originatorInfo != NULL && env_data->originatorInfo->certs != NULL) {
        for (i = 0; i < env_data->originatorInfo->certs->list.count && originator_pub_key_ptr == NULL; i++) {
            if (env_data->originatorInfo->certs->list.array[i]->present != CertificateChoices_PR_certificate) {
                SET_ERROR(RET_PKIX_UNSUPPORTED_PKIX_OBJ);
            }

            ret = kari_get_originator_public_key(kari, &env_data->originatorInfo->certs->list.array[i]->choice.certificate,
                    &originator_pub_key_ptr);
            if (ret != RET_OK && ret != RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT && ret != RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT) {
                SET_ERROR(ret);
            }
        }
    }
    if (originator_pub_key_ptr == NULL) {
        if (originator_cert_opt != NULL) {
            SET_ERROR(RET_PKIX_ENVDATA_WRONG_ORIGINATOR_CERT);
        } else {
            SET_ERROR(RET_PKIX_ENVDATA_NEED_ORIGINATOR_CERT);
        }
    }

    *encrypted_session_key = encrypted_session_key_ptr;
    encrypted_session_key_ptr = NULL;
    *rnd_bytes = rnd_bytes_ptr;
    rnd_bytes_ptr = NULL;
    *originator_pub_key = originator_pub_key_ptr;
    originator_pub_key_ptr = NULL;

cleanup:

    ba_free(subj_key_id_ext);
    ba_free(encrypted_session_key_ptr);
    ba_free(rnd_bytes_ptr);
    ba_free(originator_pub_key_ptr);
    ASN_FREE(&OCTET_STRING_desc, subjectKeyIdentifier);

    return ret;
}

int env_get_content_encryption_aid(const EnvelopedData_t *env_data, AlgorithmIdentifier_t **encr_aid)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(encr_aid != NULL);
    CHECK_PARAM(*encr_aid == NULL);

    CHECK_NOT_NULL(*encr_aid = asn_copy_with_alloc(&AlgorithmIdentifier_desc,
            &env_data->encryptedContentInfo.contentEncryptionAlgorithm));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&AlgorithmIdentifier_desc, *encr_aid);
        *encr_aid = NULL;
    }

    return ret;
}

int env_decrypt_data(const EnvelopedData_t *env_data, const ByteArray *enc_data_opt,
        const Certificate_t *originator_cert_opt, const DhAdapter *recipient_dha,
        const Certificate_t *recipient_cert, ByteArray **out)
{
    int ret = RET_OK;
    ByteArray *data = NULL;
    CipherAdapter *ca = NULL;
    ByteArray *decrypt_session_key = NULL;
    ByteArray *session_key = NULL;
    ByteArray *rnd_bytes = NULL;
    ByteArray *originator_pub_key = NULL;

    LOG_ENTRY();

    CHECK_PARAM(env_data != NULL);
    CHECK_PARAM(recipient_dha != NULL);
    CHECK_PARAM(recipient_cert != NULL);
    CHECK_PARAM(out != NULL);

    if (!env_data->encryptedContentInfo.encryptedContent
            || env_data->encryptedContentInfo.encryptedContent->size == 0) {
        if (enc_data_opt != NULL && ba_get_len(enc_data_opt) != 0) {
            data = ba_copy_with_alloc(enc_data_opt, 0, 0);
        } else {
            SET_ERROR(RET_PKIX_ENVDATA_NO_CONTENT);
        }
    } else {
        DO(asn_OCTSTRING2ba(env_data->encryptedContentInfo.encryptedContent, &data));
        if (enc_data_opt != NULL && ba_cmp(data, enc_data_opt) != 0) {
            SET_ERROR(RET_PKIX_ENVDATA_WRONG_EXTERNAL_DATA);
        }
    }

    DO(cipher_adapter_init(&env_data->encryptedContentInfo.contentEncryptionAlgorithm, &ca));
    DO(env_get_info_for_unwrap(env_data, originator_cert_opt, recipient_cert, &session_key, &rnd_bytes,
            &originator_pub_key));

    DO(unwrap_session_key(recipient_dha, session_key, rnd_bytes, originator_pub_key, &decrypt_session_key));
    DO(ca->decrypt(ca, decrypt_session_key, data, out));

cleanup:

    ba_free_private(decrypt_session_key);
    ba_free(session_key);
    ba_free(rnd_bytes);
    ba_free(originator_pub_key);
    ba_free(data);
    cipher_adapter_free(ca);

    return ret;
}
