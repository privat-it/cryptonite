/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "certificate_request_engine.h"

#include "exts.h"
#include "log_internal.h"
#include "pkix_macros_internal.h"
#include "pkix_utils.h"
#include "spki.h"
#include "certification_request.h"
#include "asn1_utils.h"
#include "cryptonite_manager.h"
#include "asn1_utils.h"
#include "ext.h"

#undef FILE_MARKER
#define FILE_MARKER "pki/engine/certificate_request_engine.c"

struct CertificateRequestEngine_st {
    const SignAdapter *sign_adapter;         /**< Адаптер выработки ЭЦП */
    Name_t *subject;
    Extension_t *subj_alt_name;
    Extension_t *subj_dir_attr;
    Extensions_t *exts;
};

int ecert_request_alloc(const SignAdapter *sa, CertificateRequestEngine **ctx)
{
    int ret = RET_OK;
    CertificateRequestEngine *cert_req_ctx = NULL;

    LOG_ENTRY();

    CHECK_PARAM(sa != NULL);
    CHECK_PARAM(ctx != NULL);

    CALLOC_CHECKED(cert_req_ctx, sizeof(CertificateRequestEngine));

    cert_req_ctx->sign_adapter = sa;

    *ctx = cert_req_ctx;
    cert_req_ctx = NULL;

cleanup:

    ecert_request_free(cert_req_ctx);

    return ret;
}

int ecert_request_set_subj_name(CertificateRequestEngine *ctx, const char *subject_name)
{
    int ret = RET_OK;
    int i;
    Name_t *subject = NULL;
    RDNSequence_t *rdn_sequence = NULL;
    RelativeDistinguishedName_t *rdn = NULL;
    AttributeTypeAndValue_t *atav = NULL;
    OBJECT_IDENTIFIER_t *oid = NULL;
    ANY_t *any = NULL;
    DirectoryString_t *dstring = NULL;
    PrintableString_t *pstring = NULL;
    UTF8String_t *ustring = NULL;
    char **subject_keys = NULL;
    char **subject_values = NULL;
    size_t count = 0;
    size_t j;

    CHECK_PARAM(ctx != NULL);

    ASN_ALLOC(rdn_sequence);

    if (subject_name) {
        DO(parse_key_value(subject_name, &subject_keys, &subject_values, &count));

        for (j = 0; j < count; j++) {
            ret = asn_create_oid_from_text((const char *)subject_keys[j], &oid);
            /* Сокращение. */
            if (ret) {
                for (i = 0; oids_get_supported_name_attr(i) != NULL; i++) {
                    if (strcmp(oids_get_supported_name_attr(i)->name, (char *)subject_keys[j])) {
                        continue;
                    }

                    DO(pkix_create_oid(oids_get_oid_numbers_by_id(oids_get_supported_name_attr(i)->oid_id), &oid));
                }
                /* OID. */
            }

            if (oid == NULL) {
                SET_ERROR(RET_PKIX_SUBJ_NAME_UNSUPPORTED);
            }

            ASN_ALLOC(dstring);

            /* Страна и серийный номер (0-й и 1-й элемент поддерживаемых атрибутов имени). */
            if (pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(oids_get_supported_name_attr(0)->oid_id))
                    || pkix_check_oid_equal(oid, oids_get_oid_numbers_by_id(oids_get_supported_name_attr(1)->oid_id))) {

                DO(asn_create_octstring(subject_values[j], strlen((char *)subject_values[j]), &pstring));

                dstring->present = DirectoryString_PR_printableString;
                DO(asn_copy(&PrintableString_desc, pstring, &dstring->choice.printableString));
                ASN_FREE(&PrintableString_desc, pstring);
                pstring = NULL;

                /* Остальные элементы атрибутов имени. */
            } else {
                DO(asn_create_octstring(subject_values[j], strlen((char *)subject_values[j]), &ustring));

                dstring->present = DirectoryString_PR_utf8String;
                DO(asn_copy(&UTF8String_desc, ustring, &dstring->choice.utf8String));
                ASN_FREE(&UTF8String_desc, ustring);
                ustring = NULL;
            }

            DO(asn_create_any(&DirectoryString_desc, dstring, &any));
            ASN_FREE(&DirectoryString_desc, dstring);
            dstring = NULL;

            ASN_ALLOC(atav);

            DO(asn_copy(&OBJECT_IDENTIFIER_desc, oid, &atav->type));
            ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
            oid = NULL;

            DO(asn_copy(&ANY_desc, any, &atav->value));
            ASN_FREE(&ANY_desc, any);
            any = NULL;

            ASN_ALLOC(rdn);
            DO(ASN_SET_ADD(&rdn->list, atav));
            atav = NULL;
            DO(ASN_SET_ADD(&rdn_sequence->list, rdn));
            rdn = NULL;
        }
    }

    ASN_ALLOC(subject);
    subject->present = Name_PR_rdnSequence;
    DO(asn_copy(&RDNSequence_desc, rdn_sequence, &subject->choice.rdnSequence));

    ASN_FREE(&Name_desc, ctx->subject);
    ctx->subject = subject;
    subject = NULL;

cleanup:

    ASN_FREE(&Name_desc, subject);
    ASN_FREE(&RDNSequence_desc, rdn_sequence);
    ASN_FREE(&RelativeDistinguishedName_desc, rdn);
    ASN_FREE(&AttributeTypeAndValue_desc, atav);
    ASN_FREE(&OBJECT_IDENTIFIER_desc, oid);
    ASN_FREE(&ANY_desc, any);
    ASN_FREE(&DirectoryString_desc, dstring);
    ASN_FREE(&PrintableString_desc, pstring);
    ASN_FREE(&UTF8String_desc, ustring);

    while (subject_keys && subject_values && count--) {
        free(subject_keys[count]);
        free(subject_values[count]);
    }

    free(subject_keys);
    free(subject_values);

    return ret;
}

int ecert_request_set_subj_alt_name(CertificateRequestEngine *ctx, const char *dns, const char *email)
{
    int ret = RET_OK;
    enum GeneralName_PR types[] = {GeneralName_PR_dNSName, GeneralName_PR_rfc822Name};
    const char *alt_names[2];
    int types_cnt = 2;

    CHECK_PARAM(ctx != NULL);

    ASN_FREE(&Extension_desc, ctx->subj_alt_name);
    ctx->subj_alt_name = NULL;

    if (dns && email) {
        alt_names[0] = dns;
        alt_names[1] = email;
        DO(ext_create_subj_alt_name_directly(false, types, alt_names, types_cnt, &ctx->subj_alt_name));
    }

cleanup:

    return ret;
}

int ecert_request_set_subj_dir_attr(CertificateRequestEngine *ctx, const char *subject_attr)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);

    ASN_FREE(&Extension_desc, ctx->subj_dir_attr);
    ctx->subj_dir_attr = NULL;

    if (subject_attr) {
        DO(ext_create_subj_dir_attr_directly(false, subject_attr, &ctx->subj_dir_attr));
    }

cleanup:

    return ret;
}

int ecert_request_add_ext(CertificateRequestEngine *ctx, const Extension_t *ext)
{
    int ret = RET_OK;

    CHECK_PARAM(ctx != NULL);
    CHECK_PARAM(ext != NULL);

    if (ctx->exts == NULL) {
        CHECK_NOT_NULL(ctx->exts = exts_alloc());
    }

    DO(exts_add_extension(ctx->exts, ext));

cleanup:

    return ret;
}

int ecert_request_generate(CertificateRequestEngine *ctx, CertificationRequest_t **cert_req)
{
    int ret = RET_OK;

    CertificationRequestInfo_t *info = NULL;
    INTEGER_t *version = NULL;
    Extension_t *ext_subj_key_id = NULL;
    Extensions_t *exts_new = NULL;
    Attribute_t *attr = NULL;
    ANY_t *wrapped_ext = NULL;
    CertificationRequest_t *certification_request = NULL;
    SubjectPublicKeyInfo_t *spki = NULL;
    int i;

    LOG_ENTRY();

    CHECK_PARAM(ctx->sign_adapter != NULL);
    CHECK_PARAM(cert_req != NULL);

    if (ctx->subject == NULL) {
        DO(ecert_request_set_subj_name(ctx, NULL));
    }

    ASN_ALLOC(info);

    DO(asn_create_integer_from_long(0, &version));
    DO(asn_copy(&INTEGER_desc, version, &info->version));

    DO(asn_copy(&Name_desc, ctx->subject, &info->subject));

    DO(ctx->sign_adapter->get_pub_key(ctx->sign_adapter, &spki));
    DO(asn_copy(&SubjectPublicKeyInfo_desc, spki, &info->subjectPKInfo));

    CHECK_NOT_NULL(exts_new = exts_alloc());

    if (ctx->subj_alt_name) {
        DO(exts_add_extension(exts_new, ctx->subj_alt_name));
    }

    if (ctx->subj_dir_attr) {
        DO(exts_add_extension(exts_new, ctx->subj_dir_attr));
    }

    /* В заявке от ИИТ всегда есть. */
    DO(ext_create_subj_key_id(false, &info->subjectPKInfo, &ext_subj_key_id));
    DO(exts_add_extension(exts_new, ext_subj_key_id));

    if (ctx->exts != NULL) {
        for (i = 0; i < ctx->exts->list.count; i++) {
            DO(exts_add_extension(exts_new, ctx->exts->list.array[i]));
        }
    }

    ASN_ALLOC(attr);
    DO(pkix_set_oid(oids_get_oid_numbers_by_id(OID_EXTENSION_REQUEST_ID), &attr->type));
    wrapped_ext = ANY_new_fromType(&Extensions_desc, exts_new);

    DO(ASN_SET_ADD(&attr->value.list, wrapped_ext));
    wrapped_ext = NULL;

    DO(ASN_SET_ADD(&info->attributes.list, attr));
    attr = NULL;

    CHECK_NOT_NULL(certification_request = creq_alloc());
    DO(creq_init_by_adapter(certification_request, info, ctx->sign_adapter));

    *cert_req = certification_request;
    certification_request = NULL;

cleanup:

    ASN_FREE(&CertificationRequestInfo_desc, info);
    ASN_FREE(&INTEGER_desc, version);
    ASN_FREE(&Extension_desc, ext_subj_key_id);
    ASN_FREE(&Attribute_desc, attr);
    ASN_FREE(&ANY_desc, wrapped_ext);

    creq_free(certification_request);
    spki_free(spki);
    exts_free(exts_new);

    return ret;
}

void ecert_request_free(CertificateRequestEngine *ctx)
{
    LOG_ENTRY();

    if (ctx) {
        ASN_FREE(&Name_desc, ctx->subject);
        ASN_FREE(&Extension_desc, ctx->subj_alt_name);
        ASN_FREE(&Extension_desc, ctx->subj_dir_attr);
        exts_free(ctx->exts);
        free(ctx);
    }
}
