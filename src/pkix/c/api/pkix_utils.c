/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>

#include "Attributes.h"
#include "asn1_utils.h"
#include "log_internal.h"
#include "oids.h"
#include "pkix_utils.h"
#include "cert.h"
#include "pkix_macros_internal.h"
#include "digest_adapter.h"
#include "cryptonite_manager.h"

#if defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
#include "iconv.h"
#endif

#define MAX_HEADER_SIZE      6
#define SBOX_SIZE            128


#undef FILE_MARKER
#define FILE_MARKER "pki/api/pkix_utils.c"

void certs_free(ByteArray **certs)
{
    int i;

    LOG_ENTRY();

    if (certs) {
        for (i = 0; certs[i] != NULL; i++) {
            ba_free(certs[i]);
        }
    }

    LOG_FREE(certs);
}

ByteArray *get_encoded_tbs_from_tbs(TBSCertificate_t *tbs)
{
    ByteArray *tbs_ba = NULL;
    int ret = RET_OK;

    CHECK_PARAM(tbs != NULL);
    DO(asn_encode_ba(&TBSCertificate_desc, tbs, &tbs_ba));

cleanup:
    return tbs_ba;
}

int get_cert_set_from_cert_array(const ByteArray **certs, CertificateSet_t **certs_set)
{
    int ret = RET_OK;
    int i;
    CertificateSet_t *certificate_set = NULL;
    CertificateChoices_t *cert = NULL;

    LOG_ENTRY();

    ASN_ALLOC(certificate_set);

    i = 0;
    while (certs != NULL && certs[i] != NULL) {
        ASN_ALLOC(cert);
        cert->present = CertificateChoices_PR_certificate;
        DO(cert_decode(&cert->choice.certificate, certs[i]));

        ASN_SET_ADD(&certificate_set->list, cert);
        cert = NULL;

        i++;
    }

    *certs_set = certificate_set;
    certificate_set = NULL;

cleanup:

    ASN_FREE(&CertificateSet_desc, certificate_set);
    ASN_FREE(&CertificateChoices_desc, cert);

    return ret;
}

int get_cert_by_sid_and_usage(const SignerIdentifier_t *sid,
        int key_usage,
        const CertificateSet_t *certs,
        Certificate_t **cert)
{
    int ret = RET_OK;

    KeyUsage_t *usage_asn1 = NULL;
    int i;
    int tmp_usage;

    LOG_ENTRY();

    CHECK_PARAM(sid != NULL);
    CHECK_PARAM(cert != NULL);

    if (!certs) {
        SET_ERROR(RET_PKIX_NO_CERTIFICATE);
    }

    for (i = 0; i < certs->list.count; i++) {
        bool required_usage = true;

        LOG_ENTRY();

        ASN_FREE(&KeyUsage_desc, usage_asn1);
        usage_asn1 = NULL;

        ret = cert_get_key_usage(&certs->list.array[i]->choice.certificate, &usage_asn1);
        if (!ret) {
            int j;
            tmp_usage = key_usage;

            for (j = 0; j < 9; j++) {
                if (tmp_usage & 0x01) {
                    int bit = 0;
                    ret = asn_BITSTRING_get_bit(usage_asn1, j, &bit);
                    if (ret || !bit) {
                        required_usage = false;
                        break;
                    }
                }

                tmp_usage = tmp_usage >> 1;
            }
        }

        if (!required_usage) {
            continue;
        }

        if (cert_check_sid(&certs->list.array[i]->choice.certificate, sid)) {
            CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&Certificate_desc, &certs->list.array[i]->choice.certificate));
            ret = RET_OK;
            goto cleanup;
        }
    }

    SET_ERROR(RET_PKIX_NO_CERTIFICATE);

cleanup:

    ASN_FREE(&KeyUsage_desc, usage_asn1);

    return ret;
}

bool is_dstu_le_params(const OBJECT_IDENTIFIER_t *oid)
{
    LOG_ENTRY();

    return pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_LE_ID))
            || pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_ONB_LE_ID));
}

bool is_dstu_be_params(const OBJECT_IDENTIFIER_t *oid)
{
    LOG_ENTRY();

    return pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_BE_ID))
            || pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_ONB_BE_ID));
}

int sign_ba_to_bs(const ByteArray *sign, const AlgorithmIdentifier_t *aid, BIT_STRING_t *sign_bitstring)
{
    ECDSA_Sig_Value_t *ec_str = NULL;
    OCTET_STRING_t *octet_sign = NULL;
    ByteArray *ba_buf = NULL;
    ByteArray *zero_ba = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(sign != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sign_bitstring != NULL);

    if (is_dstu_le_params(&aid->algorithm)) {
        ASN_ALLOC(octet_sign);
        DO(asn_create_octstring_from_ba(sign, &octet_sign));
        DO(asn_encode_ba(&OCTET_STRING_desc, octet_sign, &ba_buf));
        DO(asn_create_bitstring_from_ba(ba_buf, &sign_bitstring));
    } else if (is_dstu_be_params(&aid->algorithm)) {
        DO(asn_create_octstring_from_ba(sign, &octet_sign));
        DO(asn_encode_ba(&OCTET_STRING_desc, octet_sign, &ba_buf));
        DO(asn_create_bitstring_from_ba(ba_buf, &sign_bitstring));
    } else if (pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
            pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
            pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
            pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID)) ||
            pkix_check_oid_parent(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID))) {

        ASN_ALLOC(ec_str);

        CHECK_NOT_NULL(r = ba_copy_with_alloc(sign, 0, ba_get_len(sign) >> 1));
        CHECK_NOT_NULL(s = ba_copy_with_alloc(sign, ba_get_len(sign) >> 1, 0));
        CHECK_NOT_NULL(zero_ba = ba_alloc_by_len(1));
        DO(ba_set(zero_ba, 0x00));
        DO(ba_swap(r));
        DO(ba_append(zero_ba, 0, 0, r));
        DO(ba_swap(r));
        DO(ba_swap(s));
        DO(ba_append(zero_ba, 0, 0, s));
        DO(ba_swap(s));
        DO(asn_ba2INTEGER(r, &ec_str->r));
        DO(asn_ba2INTEGER(s, &ec_str->s));

        DO(asn_encode_ba(&ECDSA_Sig_Value_desc, ec_str, &ba_buf));

        DO(asn_create_bitstring_from_ba(ba_buf, &sign_bitstring));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    ba_free(r);
    ba_free(s);
    ba_free(zero_ba);
    ba_free(ba_buf);
    ASN_FREE(&OCTET_STRING_desc, octet_sign);
    ASN_FREE(&ECDSA_Sig_Value_desc, ec_str);

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&BIT_STRING_desc, sign_bitstring);
    }

    return ret;
}

int sign_ba_to_os(const ByteArray *sign,
        const AlgorithmIdentifier_t *aid,
        OCTET_STRING_t **sign_octet)
{
    int ret = RET_OK;
    ECDSA_Sig_Value_t *ec_params = NULL;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *decode = NULL;
    ByteArray *zero_ba = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sign != NULL);
    CHECK_PARAM(aid != NULL);

    if (is_dstu_le_params(&aid->algorithm)) {
        DO(asn_create_octstring_from_ba(sign, sign_octet));
    } else if (is_dstu_be_params(&aid->algorithm)) {
        DO(asn_create_octstring_from_ba(sign, sign_octet));
        SWAP_BYTES(sign, (*sign_octet)->buf, (int)ba_get_len(sign));
    } else if (pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID))) {
        ASN_ALLOC(ec_params);
        CHECK_NOT_NULL(r = ba_copy_with_alloc(sign, 0, ba_get_len(sign) >> 1));
        CHECK_NOT_NULL(s = ba_copy_with_alloc(sign, ba_get_len(sign) >> 1, 0));
        CHECK_NOT_NULL(zero_ba = ba_alloc_by_len(1));

        DO(ba_set(zero_ba, 0x00));
        DO(ba_swap(r));
        DO(ba_append(zero_ba, 0, 0, r));
        DO(ba_swap(r));
        DO(ba_swap(s));
        DO(ba_append(zero_ba, 0, 0, s));
        DO(ba_swap(s));
        DO(asn_ba2INTEGER(r, &ec_params->r));
        DO(asn_ba2INTEGER(s, &ec_params->s));
        DO(asn_encode_ba(&ECDSA_Sig_Value_desc, ec_params, &decode));
        DO(asn_create_octstring_from_ba(decode, sign_octet));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&OCTET_STRING_desc, *sign_octet);
    }
    ba_free(r);
    ba_free(s);
    ba_free(decode);
    ba_free(zero_ba);
    ASN_FREE(&ECDSA_Sig_Value_desc, ec_params);

    return ret;
}

int sign_bs_to_ba(const BIT_STRING_t *sign_bitstring, const AlgorithmIdentifier_t *aid,
        ByteArray **sign)
{
    int ret = RET_OK;
    ByteArray *r = NULL;
    ByteArray *s = NULL;
    ByteArray *rs_ba = NULL;
    OCTET_STRING_t *octet_sign = NULL;
    ECDSA_Sig_Value_t *rs = NULL;
    LOG_ENTRY();

    CHECK_PARAM(sign_bitstring != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sign != NULL);

    *sign = NULL;

    if (is_dstu_le_params(&aid->algorithm)) {

        CHECK_NOT_NULL(octet_sign = asn_decode_with_alloc(&OCTET_STRING_desc, sign_bitstring->buf, sign_bitstring->size));
        CHECK_NOT_NULL(*sign = ba_alloc_from_uint8(octet_sign->buf, octet_sign->size));

    } else if (is_dstu_be_params(&aid->algorithm)) {

        CHECK_NOT_NULL(octet_sign = asn_decode_with_alloc(&OCTET_STRING_desc, sign_bitstring->buf, sign_bitstring->size));
        CHECK_NOT_NULL(*sign = ba_alloc_from_uint8(octet_sign->buf, octet_sign->size));
        DO(ba_swap(*sign));
    } else if ( pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA1_ID)) ||
            pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA224_ID)) ||
            pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA256_ID)) ||
            pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA384_ID)) ||
            pkix_check_oid_equal(&aid->algorithm, oids_get_oid_numbers_by_id(OID_ECDSA_WITH_SHA512_ID))) {
        ASN_ALLOC(rs);
        DO(asn_BITSTRING2ba(sign_bitstring, &rs_ba));
        DO(asn_decode_ba(&ECDSA_Sig_Value_desc, rs, rs_ba));
        DO(asn_INTEGER2ba(&rs->r, &r));
        DO(asn_INTEGER2ba(&rs->s, &s));

        if (ba_get_buf(r)[ba_get_len(r) - 1] == 0) {
            ba_change_len(r, ba_get_len(r) - 1);
        }
        if (ba_get_buf(s)[ba_get_len(s) - 1] == 0) {
            ba_change_len(s, ba_get_len(s) - 1);
        }

        CHECK_NOT_NULL(*sign = ba_join(r, s));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    if (ret != RET_OK) {
        free(*sign);
    }
    ba_free(r);
    ba_free(s);
    ba_free(rs_ba);
    ASN_FREE(&ECDSA_Sig_Value_desc, rs);
    ASN_FREE(&OCTET_STRING_desc, octet_sign);

    return ret;
}

int sign_os_to_ba(const OCTET_STRING_t *sign_os,
        const AlgorithmIdentifier_t *aid,
        ByteArray **sign)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(sign_os != NULL);
    CHECK_PARAM(aid != NULL);
    CHECK_PARAM(sign != NULL);

    *sign = NULL;

    if (is_dstu_le_params(&aid->algorithm)) {
        CHECK_NOT_NULL(*sign = ba_alloc_from_uint8(sign_os->buf, sign_os->size));
    } else if (is_dstu_be_params(&aid->algorithm)) {
        CHECK_NOT_NULL(*sign = ba_alloc_from_uint8(sign_os->buf, sign_os->size));
        DO(ba_swap(*sign));
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

cleanup:

    return ret;
}

static int get_next_key(const char **start, char **key, char **value)
{
    int key_size;
    int val_size;
    int ret = RET_OK;
    char *lbracket = strchr((char *)*start, '{');
    char *rbracket = strchr((char *)*start, '}');
    char *eq = strchr((char *)*start, '=');

    LOG_ENTRY();

    CHECK_PARAM(lbracket != NULL);
    CHECK_PARAM(rbracket != NULL);
    CHECK_PARAM(eq != NULL);
    CHECK_PARAM(lbracket <= eq);
    CHECK_PARAM(lbracket <= rbracket);
    CHECK_PARAM(eq <= rbracket);

    key_size = (int) (eq - lbracket - 1);
    val_size = (int) (rbracket - eq - 1);

    if (key_size <= 0 || val_size <= 0) {
        LOG_ERROR();
        SET_ERROR(RET_INVALID_PARAM);
    }
    CALLOC_CHECKED(*key, key_size + 1);
    CALLOC_CHECKED(*value, val_size + 1);

    memcpy(*key, lbracket + 1, key_size);
    memcpy(*value, eq + 1, val_size);

    (*key)[key_size] = '\0';
    (*value)[val_size] = '\0';

    *start = strchr((*start + 1), '{');
cleanup:
    return ret;
}

int parse_key_value(const char *str, char ***keys, char ***values, size_t *count)
{
    int ret = RET_OK;
    char *key = NULL;
    char *value = NULL;
    const char *ptr;
    const char *end = str + strlen(str);

    LOG_ENTRY();

    *count = 0;
    ptr = str;

    while (ptr && (ptr < end)) {

        int i = 0;
        key = NULL;
        value = NULL;

        DO(get_next_key(&ptr, &key, &value));

        while (key[i]) {
            key[i] = toupper(key[i]);
            i++;
        }

        REALLOC_CHECKED(*keys, (*count + 1) * (sizeof * keys), *keys);
        REALLOC_CHECKED(*values, (*count + 1) * (sizeof * values), *values);

        (*keys)[*count] = key;
        (*values)[*count] = value;

        (*count)++;
    }

    return RET_OK;

cleanup:

    free(key);
    free(value);

    return ret;
}

int convert_pub_key_bs_to_ba(const OBJECT_IDENTIFIER_t *oid,
        const BIT_STRING_t *pub_key_asn,
        ByteArray **pub_key_ba)
{
    int ret = RET_OK;

    uint8_t *buffer = NULL;
    size_t buffer_len = 0;

    INTEGER_t *ikey = NULL;
    OCTET_STRING_t *okey = NULL;
    unsigned char *pub_key_bytes = NULL;
    size_t len;

    LOG_ENTRY();

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(pub_key_asn != NULL);
    CHECK_PARAM(pub_key_ba != NULL);

    DO(asn_BITSTRING2bytes(pub_key_asn, &buffer, &buffer_len));

    if (pkix_check_oid_parent(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {

        CHECK_NOT_NULL(okey = asn_decode_with_alloc(&OCTET_STRING_desc, buffer, buffer_len));
        DO(asn_OCTSTRING2bytes(okey, &pub_key_bytes, &len));

        if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_PB_BE_ID))
                || pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_ONB_BE_ID))) {
            SWAP_BYTES(pub_key_bytes, pub_key_bytes, (int)len);
        }
    } else if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID))) {
        DO(asn_BITSTRING2ba(pub_key_asn, pub_key_ba));
        goto cleanup;
    } else {
        SET_ERROR(RET_PKIX_UNSUPPORTED_SIGN_ALG);
    }

    CHECK_NOT_NULL(*pub_key_ba = ba_alloc_from_uint8(pub_key_bytes, len));

cleanup:

    free(buffer);
    free(pub_key_bytes);
    ASN_FREE(&INTEGER_desc, ikey);
    ASN_FREE(&OCTET_STRING_desc, okey);

    return ret;
}

int convert_pubkey_bytes_to_bitstring(const OBJECT_IDENTIFIER_t *signature_oid,
        const ByteArray *pub_key,
        BIT_STRING_t **out_pub_key_bs)
{
    int ret = RET_OK;

    OCTET_STRING_t *pub_key_os = NULL;
    INTEGER_t *pub_key_integer = NULL;
    BIT_STRING_t *bs = NULL;

    LOG_ENTRY();

    if (pkix_check_oid_parent(signature_oid, oids_get_oid_numbers_by_id(OID_PKI_DSTU4145_WITH_GOST3411_ID))) {

        if (is_dstu_le_params(signature_oid)) {
            DO(asn_create_octstring_from_ba(pub_key, &pub_key_os));
        } else {
            DO(ba_swap(pub_key));
            DO(asn_create_octstring_from_ba(pub_key, &pub_key_os));
        }

        DO(asn_create_bitstring_from_octstring(pub_key_os, &bs));

    } else if (pkix_check_oid_parent(signature_oid, oids_get_oid_numbers_by_id(OID_EC_PUBLIC_KEY_TYPE_ID))) {
        DO(asn_create_bitstring_from_ba(pub_key, &bs));
    } else {
        DO(asn_create_bitstring_from_ba(pub_key, &bs));
    }

    *out_pub_key_bs = bs;

cleanup:

    ASN_FREE(&INTEGER_desc, pub_key_integer);
    ASN_FREE(&OCTET_STRING_desc, pub_key_os);

    if (ret != RET_OK) {
        ASN_FREE(&BIT_STRING_desc, bs);
    }

    return ret;
}

int init_attr(Attribute_t **attr, const OidNumbers *oid, asn_TYPE_descriptor_t *descriptor, void *value)
{
    int ret = RET_OK;
    ANY_t *any = NULL;

    LOG_ENTRY();

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(value != NULL);
    CHECK_PARAM(descriptor != NULL);

    ASN_ALLOC(*attr);
    DO(pkix_set_oid(oid, &(*attr)->type));
    CHECK_NOT_NULL(any = ANY_new_fromType(descriptor, value));
    DO(ASN_SET_ADD(&(*attr)->value.list, any));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&Attribute_desc, *attr);
        *attr = NULL;
    }

    return ret;
}

int get_attr_by_oid(const Attributes_t *attrs, const OBJECT_IDENTIFIER_t *oid, Attribute_t **attr)
{
    int ret = RET_OK;
    int i;
    long *oid_numbers = NULL;
    size_t oid_numbers_len;
    Attribute_t *attribute = NULL;

    LOG_ENTRY();

    CHECK_PARAM(oid != NULL);
    CHECK_PARAM(attrs != NULL);
    CHECK_PARAM(attr != NULL);

    for (i = 0; i < attrs->list.count; i++) {
        Attribute_t *cur_attr = attrs->list.array[i];

        if (!cur_attr) {
            continue;
        }
        DO(asn_get_oid_arcs(oid, &oid_numbers, &oid_numbers_len));

        if (asn_check_oid_equal(&cur_attr->type, oid_numbers, oid_numbers_len)) {
            CHECK_NOT_NULL(attribute = asn_copy_with_alloc(&Attribute_desc, (void *)cur_attr));
            break;
        }

        free(oid_numbers);
        oid_numbers = NULL;
    }

    if (attribute) {
        *attr = attribute;
    } else {
        LOG_ERROR();
        ASN_FREE(&Attribute_desc, attribute);

        SET_ERROR(RET_PKIX_ATTRIBUTE_NOT_FOUND);
    }

cleanup:

    free(oid_numbers);

    return ret;
}

static int get_cert_by_sid(const CertificateSet_t *cert_set, const SignerIdentifier_t *sid, Certificate_t **cert)
{
    int i;
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(sid != NULL);

    if (cert_set == NULL) {
        return RET_OK;
    }

    *cert = NULL;
    for (i = 0; i < cert_set->list.count; i++) {
        if ((cert_set->list.array[i]->present == CertificateChoices_PR_certificate)
                && cert_check_sid(&cert_set->list.array[i]->choice.certificate, sid)) {
            CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&Certificate_desc, &cert_set->list.array[i]->choice.certificate));
            break;
        }
    }

cleanup:

    return ret;
}

static int get_cert_by_ski(const CertificateSet_t *cert_set, const ByteArray *subj_key_id, Certificate_t **cert)
{
    int i;
    int ret = RET_OK;
    ByteArray *cert_subj_key_id = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cert != NULL);
    CHECK_PARAM(subj_key_id != NULL);

    if (cert_set == NULL) {
        *cert = NULL;
        return RET_OK;
    }

    *cert = NULL;
    for (i = 0; i < cert_set->list.count; i++) {
        if (cert_set->list.array[i]->present == CertificateChoices_PR_certificate) {
            DO(cert_get_subj_key_id(&cert_set->list.array[i]->choice.certificate, &cert_subj_key_id));

            if (ba_cmp(cert_subj_key_id, subj_key_id) == 0) {
                CHECK_NOT_NULL(*cert = asn_copy_with_alloc(&Certificate_desc, &cert_set->list.array[i]->choice.certificate));
                break;
            }

            ba_free(cert_subj_key_id);
            cert_subj_key_id = NULL;
        }
    }

cleanup:

    ba_free(cert_subj_key_id);

    return ret;
}

int get_cert_set_by_sid(const CertificateSet_t *cert_set_in, const SignerIdentifier_t *sid,
        CertificateSet_t **cert_set_out)
{
    Certificate_t *cert = NULL;
    CertificateChoices_t *cert_choices = NULL;
    int ret = RET_OK;
    ByteArray *subj_key_id = NULL;
    ByteArray *auth_key_id = NULL;
    CertificateSet_t *cert_set = NULL;

    LOG_ENTRY();

    DO(get_cert_by_sid(cert_set_in, sid, &cert));
    if (cert == NULL) {
        *cert_set_out = NULL;
        return RET_OK;
    }

    while (cert != NULL) {
        if (cert_set == NULL) {
            ASN_ALLOC(cert_set);
        }

        ASN_ALLOC(cert_choices);
        cert_choices->present = CertificateChoices_PR_certificate;
        DO(asn_copy(&Certificate_desc, cert, &cert_choices->choice.certificate));
        DO(ASN_SET_ADD(&(cert_set->list), cert_choices));
        cert_choices = NULL;

        DO(cert_get_auth_key_id(cert, &auth_key_id));

        if ((subj_key_id != NULL) && ba_cmp(subj_key_id, auth_key_id) == 0) {
            break;
        }

        ASN_FREE(&Certificate_desc, cert);
        cert = NULL;

        DO(get_cert_by_ski(cert_set_in, auth_key_id, &cert));

        ba_free(subj_key_id);
        subj_key_id = auth_key_id;
        auth_key_id = NULL;
    }

    *cert_set_out = cert_set;
    cert_set = NULL;

cleanup:

    ASN_FREE(&Certificate_desc, cert);
    ASN_FREE(&CertificateChoices_desc, cert_choices);
    ASN_FREE(&CertificateSet_desc, cert_set);

    ba_free(subj_key_id);
    ba_free(auth_key_id);

    return ret;
}

int utf16be_to_utf8(const unsigned char *in, size_t in_len, char **out)
{
    int ret = RET_OK;

    CHECK_PARAM(in != NULL);
    CHECK_PARAM(out != NULL);

#ifdef _WIN32

    int i;
    wchar_t *in_le = NULL;
    int char_len = 0;
    int wchar_len = (int)(in_len / 2);

    MALLOC_CHECKED(in_le, wchar_len * sizeof(wchar_t));

    /* LE to BE  UTF-16 */
    for (i = 0; i < wchar_len; i++) {
        in_le[i] = (in[2 * i] << 8) & 0xffff;
        in_le[i] |= in[2 * i + 1] & 0xff;
    }

    char_len = WideCharToMultiByte(CP_UTF8, 0, in_le, wchar_len, 0, 0, NULL, NULL);

    MALLOC_CHECKED(*out, (char_len + 1) * sizeof(char));

    WideCharToMultiByte(CP_UTF8, 0, in_le, wchar_len, *out, char_len, NULL, NULL);

    (*out)[char_len] = 0;

cleanup:

    free(in_le);

#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    char *_out = NULL;
    size_t out_len = in_len;
    char *_out_ptr;
    iconv_t cd;

    LOG_ENTRY();

    MALLOC_CHECKED(_out, in_len);

    _out_ptr = _out;

    cd = iconv_open("UTF-8", "UTF-16BE");

    if (cd == (iconv_t)(-1) || iconv(cd, (char **)&in, &in_len, &_out_ptr, &out_len) == (size_t) - 1) {
        free(_out);
        _out = NULL;
        ret = RET_INVALID_PARAM;
        ERROR_CREATE(ret);
    }

    _out_ptr[0] = 0;
    *out = _out;

    iconv_close(cd);

cleanup:
#else
#error Unsupported platform
#endif
    return ret;
}

int utf8_to_utf16be(const char *in, unsigned char **out, size_t *out_len)
{
    int ret = RET_OK;

    CHECK_PARAM(in);
    CHECK_PARAM(out);
    CHECK_PARAM(out_len);

#ifdef _WIN32

    wchar_t *wout = NULL;
    int wchar_len = 0;
    int i;

    wchar_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, 0, 0);
    if (!wchar_len) {
        SET_ERROR(RET_PKIX_INVALID_UTF8_STR);
    }

    MALLOC_CHECKED(wout, wchar_len * sizeof(wchar_t));

    wchar_len = MultiByteToWideChar(CP_UTF8, 0, in, -1, wout, wchar_len);
    if (!wchar_len) {
        SET_ERROR(RET_PKIX_INVALID_UTF8_STR);
    }

    *out_len = wchar_len * 2;
    MALLOC_CHECKED(*out, (*out_len) * sizeof(char));

    /* LE to BE  UTF-16 */
    for (i = 0; i < wchar_len; i++) {
        (*out)[2 * i] = wout[i] >> 8;
        (*out)[2 * i + 1] = wout[i] & 0xff;
    }

    free(wout);

#elif defined(__linux__) || defined(__APPLE__) || defined(__GNUC__)
    size_t in_len = strlen(in) + 1;
    char *_out = (char *) malloc(2 * in_len);
    size_t _out_len = 2 * in_len;
    char *_out_ptr = _out;
    iconv_t cd;

    if (_out == NULL) {
        SET_ERROR(RET_MEMORY_ALLOC_ERROR);
    }
    LOG_ENTRY();
    cd = iconv_open("UTF-16BE", "UTF-8");

    if (cd == (iconv_t)(-1) || iconv(cd, (char **)&in, &in_len, &_out_ptr, &_out_len) == (size_t) - 1) {
        free(_out);
        _out = NULL;
        _out_len = 0;
        SET_ERROR(RET_PKIX_INVALID_UTF8_STR);
    }

    *out = (unsigned char *)_out;
    *out_len = (size_t)(_out_ptr - _out);

    iconv_close(cd);

#else
#error Unsupported platform
#endif
cleanup:
    return ret;
}

char *dupstr(const char *str)
{
    char *str_cpy = NULL;

    if (str) {
        str_cpy = malloc(strlen(str) + 1);
        if (str_cpy) {
            strcpy(str_cpy, str);
        } else {
            ERROR_CREATE(RET_MEMORY_ALLOC_ERROR);
        }
    }

    return str_cpy;
}

bool pkix_check_oid_parent(const OBJECT_IDENTIFIER_t *oid, const OidNumbers *parent_oid)
{
    if (parent_oid != NULL) {
        return asn_check_oid_parent(oid, parent_oid->numbers, parent_oid->numbers_len);
    } else {
        return false;
    }
}

bool pkix_check_oid_equal(const OBJECT_IDENTIFIER_t *oid, const OidNumbers *oid_arr)
{
    if (oid_arr != NULL) {
        return asn_check_oid_equal(oid, oid_arr->numbers, oid_arr->numbers_len);
    } else {
        return false;
    }
}

int pkix_create_oid(const OidNumbers *oid, OBJECT_IDENTIFIER_t **dst)
{
    int ret = RET_OK;

    CHECK_PARAM(oid);
    DO(asn_create_oid(oid->numbers, oid->numbers_len, dst));

cleanup:

    return ret;
}

int pkix_set_oid(const OidNumbers *oid, OBJECT_IDENTIFIER_t *dst)
{
    int ret = RET_OK;

    CHECK_PARAM(oid);
    DO(asn_set_oid(oid->numbers, oid->numbers_len, dst));

cleanup:

    return ret;
}

int pkix_get_key_id_from_spki(const SubjectPublicKeyInfo_t *spki, ByteArray **key_id)
{
    ByteArray *pubkey = NULL;
    DigestAdapter *da = NULL;
    int ret = RET_OK;

    CHECK_PARAM(spki != NULL);
    CHECK_PARAM(key_id != NULL);

    DO(asn_BITSTRING2ba(&spki->subjectPublicKey, &pubkey));
    DO(digest_adapter_init_by_aid(&spki->algorithm, &da));

    DO(da->update(da, pubkey));
    DO(da->final(da, key_id));

cleanup:

    digest_adapter_free(da);
    ba_free(pubkey);

    return ret;
}
