/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CertificateChoices.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CertificateChoices.c"

static asn_TYPE_member_t asn_MBR_CertificateChoices_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateChoices, choice.certificate),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &Certificate_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "certificate"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateChoices, choice.extendedCertificate),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &ExtendedCertificate_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "extendedCertificate"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateChoices, choice.v1AttrCert),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &AttributeCertificateV1_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "v1AttrCert"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateChoices, choice.v2AttrCert),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &AttributeCertificateV2_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "v2AttrCert"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificateChoices, choice.other),
        (ASN_TAG_CLASS_CONTEXT | (3 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &OtherCertificateFormat_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "other"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_CertificateChoices_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* certificate */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* extendedCertificate */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 }, /* v1AttrCert */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 3, 0, 0 }, /* v2AttrCert */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 4, 0, 0 } /* other */
};
static asn_CHOICE_specifics_t asn_SPC_CertificateChoices_specs_1 = {
    sizeof(struct CertificateChoices),
    offsetof(struct CertificateChoices, _asn_ctx),
    offsetof(struct CertificateChoices, present),
    sizeof(((struct CertificateChoices *)0)->present),
    asn_MAP_CertificateChoices_tag2el_1,
    5,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t CertificateChoices_desc = {
    "CertificateChoices",
    "CertificateChoices",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    0,    /* No effective tags (pointer) */
    0,    /* No effective tags (count) */
    0,    /* No tags (pointer) */
    0,    /* No tags (count) */
    0,    /* No PER visible constraints */
    asn_MBR_CertificateChoices_1,
    5,    /* Elements count */
    &asn_SPC_CertificateChoices_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CertificateChoices_desc(void)
{
    return &CertificateChoices_desc;
}
