/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include <stdlib.h>
#include <stdbool.h>

#include "asn1_utils.h"
#include "log_internal.h"
#include "oids.h"
#include "pkix_utils.h"
#include "content_info.h"
#include "pkix_macros_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/api/content_info.c"

ContentInfo_t *cinfo_alloc(void)
{
    ContentInfo_t *cinfo = NULL;
    int ret = RET_OK;

    LOG_ENTRY();

    ASN_ALLOC(cinfo);

cleanup:

    return cinfo;
}

void cinfo_free(ContentInfo_t *cinfo)
{
    LOG_ENTRY();

    ASN_FREE(&ContentInfo_desc, cinfo);
}

int cinfo_init_by_signed_data(ContentInfo_t *cinfo, const SignedData_t *sdata)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(sdata != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_SIGNED_DATA_ID), &cinfo->contentType));
    DO(asn_set_any(&SignedData_desc, (void *)sdata, &cinfo->content));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
    }

    return ret;
}

int cinfo_init_by_digest_data(ContentInfo_t *cinfo, const DigestedData_t *ddata)
{
    int ret = RET_OK;

    ANY_t *pcont = NULL;
    ContentType_t *dtype = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(ddata != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(pkix_create_oid(oids_get_oid_numbers_by_id(OID_DIG_OID_ID), &dtype));
    DO(asn_copy(&ContentType_desc, dtype, &cinfo->contentType));

    CHECK_NOT_NULL(pcont = ANY_new_fromType(&ANY_desc, (void *)ddata));
    DO(asn_copy(&DigestedData_desc, pcont, &cinfo->content));

cleanup:

    ASN_FREE(&ANY_desc, pcont);
    ASN_FREE(&ContentType_desc, dtype);
    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
    }

    return ret;
}

int cinfo_init_by_encrypted_data(ContentInfo_t *cinfo, const EncryptedData_t *encr_data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(encr_data != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ENC_OID_ID), &cinfo->contentType));
    DO(asn_set_any(&EncryptedData_desc, (void *)encr_data, &cinfo->content));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
    }

    return ret;
}

int cinfo_init_by_data(ContentInfo_t *cinfo, const ByteArray *data)
{
    int ret = RET_OK;
    OCTET_STRING_t *data_os = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(data != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_DATA_ID), &cinfo->contentType));

    DO(asn_create_octstring_from_ba(data, &data_os));
    DO(asn_set_any(&OCTET_STRING_desc, (void *)data_os, &cinfo->content));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
    }
    ASN_FREE(&OCTET_STRING_desc, data_os);

    return ret;
}

int cinfo_init_by_enveloped_data(ContentInfo_t *cinfo, const EnvelopedData_t *env_data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(env_data != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_ENVELOPED_DATA_ID), &cinfo->contentType));
    DO(asn_set_any(&EnvelopedData_desc, (void *)env_data, &cinfo->content));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
    }

    return ret;
}

int cinfo_init_by_any_content(ContentInfo_t *cinfo, const ContentType_t *ctype, const ANY_t *content)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(ctype != NULL);
    CHECK_PARAM(content != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(asn_copy(&ContentType_desc, ctype, &cinfo->contentType));
    DO(asn_copy(&ANY_desc, content, &cinfo->content));

cleanup:

//    if () {
//        ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);
//    }

    return ret;
}

int cinfo_encode(const ContentInfo_t *cinfo, ByteArray **out)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(out != NULL);

    DO(asn_encode_ba(&ContentInfo_desc, cinfo, out));
cleanup:
    return ret;
}

int cinfo_decode(ContentInfo_t *cinfo, const ByteArray *in)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(in != NULL);

    ASN_FREE_CONTENT_PTR(&ContentInfo_desc, cinfo);

    DO(asn_decode_ba(&ContentInfo_desc, cinfo, in));

cleanup:

    return ret;
}

int cinfo_has_content(const ContentInfo_t *cinfo, bool *flag)
{
    int ret = RET_OK;
    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(flag != NULL);

    *flag = (NULL != cinfo->content.buf && 0 != cinfo->content.size);

cleanup:

    return ret;
}

int cinfo_get_data(const ContentInfo_t *cinfo, ByteArray **data)
{
    int ret = RET_OK;
    OCTET_STRING_t *content = NULL;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(data != NULL);

    if (!pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_DATA_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_DATA);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_DATA);
    }

    CHECK_NOT_NULL(content = asn_any2type(&cinfo->content, &OCTET_STRING_desc));
    DO(asn_OCTSTRING2ba(content, data));

cleanup:

    ASN_FREE(&OCTET_STRING_desc, content);

    return ret;
}

int cinfo_get_signed_data(const ContentInfo_t *cinfo, SignedData_t **sdata)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(sdata != NULL);

    if (!pkix_check_oid_parent(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_SIGNED_DATA_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_SIGNED_DATA);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_SIGNED_DATA);
    }

    CHECK_NOT_NULL(*sdata = asn_any2type(&cinfo->content, &SignedData_desc));

cleanup:

    return ret;
}

int cinfo_get_digested_data(const ContentInfo_t *cinfo, DigestedData_t **ddata)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(ddata != NULL);

    if (!pkix_check_oid_parent(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_DIG_OID_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_DIGESTED_DATA);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_DIGESTED_DATA);
    }

    CHECK_NOT_NULL(*ddata = asn_any2type(&cinfo->content, &DigestedData_desc));

cleanup:

    return ret;
}

int cinfo_get_encrypted_data(const ContentInfo_t *cinfo, EncryptedData_t **encr_data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(encr_data != NULL);

    if (!pkix_check_oid_parent(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_ENC_OID_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_ENCRYPTED_DATA);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_ENCRYPTED_DATA);
    }

    CHECK_NOT_NULL(*encr_data = asn_any2type(&cinfo->content, &EncryptedData_desc));

cleanup:

    return ret;
}

int cinfo_get_enveloped_data(const ContentInfo_t *cinfo, EnvelopedData_t **env_data)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(env_data != NULL);

    if (!pkix_check_oid_parent(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_ENVELOPED_DATA_ID))) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_ENVELOPED_DATA);
    }

    if (!cinfo->content.buf || !cinfo->content.size) {
        LOG_ERROR();
        SET_ERROR(RET_PKIX_CINFO_NOT_ENVELOPED_DATA);
    }

    CHECK_NOT_NULL(*env_data = asn_any2type(&cinfo->content, &EnvelopedData_desc));

cleanup:

    return ret;
}

int cinfo_get_any_content(const ContentInfo_t *cinfo, ContentType_t **ctype, ANY_t **content)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(ctype != NULL);
    CHECK_PARAM(content != NULL);
    CHECK_PARAM(*ctype == NULL);
    CHECK_PARAM(*content == NULL);

    CHECK_NOT_NULL(*ctype = asn_copy_with_alloc(&ContentType_desc, &cinfo->contentType));
    CHECK_NOT_NULL(*content = asn_copy_with_alloc(&ANY_desc, &cinfo->content));

cleanup:

    if (ret != RET_OK) {
        ASN_FREE(&ContentType_desc, *ctype);
        *ctype = NULL;

        ASN_FREE(&ANY_desc, *content);
        *content = NULL;
    }

    return ret;
}

int cinfo_get_type(const ContentInfo_t *cinfo, CinfoType *type)
{
    int ret = RET_OK;

    LOG_ENTRY();

    CHECK_PARAM(cinfo != NULL);
    CHECK_PARAM(type != NULL);

    if (pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_DATA_ID))) {
        *type = CONTENT_DATA;
    } else if (pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_SIGNED_DATA_ID))) {
        *type = CONTENT_SIGNED;
    } else if (pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_DIG_OID_ID))) {
        *type = CONTENT_DIGESTED;
    } else if (pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_ENC_OID_ID))) {
        *type = CONTENT_ENCRYPTED;
    } else if (pkix_check_oid_equal(&cinfo->contentType, oids_get_oid_numbers_by_id(OID_ENVELOPED_DATA_ID))) {
        *type = CONTENT_ENVELOPED;
    } else {
        *type = CONTENT_UNKNOWN;
    }

cleanup:

    return ret;
}
