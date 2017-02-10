/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CertificationRequestInfo.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CertificationRequestInfo.c"

static asn_TYPE_member_t asn_MBR_CertificationRequestInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequestInfo, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &Version_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequestInfo, subject),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subject"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequestInfo, subjectPKInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &SubjectPublicKeyInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "subjectPKInfo"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CertificationRequestInfo, attributes),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &Attributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "attributes"
    },
};
static const ber_tlv_tag_t CertificationRequestInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CertificationRequestInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 1 }, /* rdnSequence */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 0 }, /* subjectPKInfo */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, 0, 0 } /* attributes */
};
static asn_SEQUENCE_specifics_t asn_SPC_CertificationRequestInfo_specs_1 = {
    sizeof(struct CertificationRequestInfo),
    offsetof(struct CertificationRequestInfo, _asn_ctx),
    asn_MAP_CertificationRequestInfo_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CertificationRequestInfo_desc = {
    "CertificationRequestInfo",
    "CertificationRequestInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CertificationRequestInfo_desc_tags_1,
    sizeof(CertificationRequestInfo_desc_tags_1)
    / sizeof(CertificationRequestInfo_desc_tags_1[0]), /* 1 */
    CertificationRequestInfo_desc_tags_1,    /* Same as above */
    sizeof(CertificationRequestInfo_desc_tags_1)
    / sizeof(CertificationRequestInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CertificationRequestInfo_1,
    4,    /* Elements count */
    &asn_SPC_CertificationRequestInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CertificationRequestInfo_desc(void)
{
    return &CertificationRequestInfo_desc;
}
