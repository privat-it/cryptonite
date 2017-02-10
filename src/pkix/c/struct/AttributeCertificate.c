/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "AttributeCertificate.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/AttributeCertificate.c"

static asn_TYPE_member_t asn_MBR_AttributeCertificate_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct AttributeCertificate, acinfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AttributeCertificateInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "acinfo"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct AttributeCertificate, signatureAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct AttributeCertificate, signatureValue),
        (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)),
        0,
        &BIT_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "signatureValue"
    },
};
static const ber_tlv_tag_t AttributeCertificate_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AttributeCertificate_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (3 << 2)), 2, 0, 0 }, /* signatureValue */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 1 }, /* acinfo */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 0 } /* signatureAlgorithm */
};
static asn_SEQUENCE_specifics_t asn_SPC_AttributeCertificate_specs_1 = {
    sizeof(struct AttributeCertificate),
    offsetof(struct AttributeCertificate, _asn_ctx),
    asn_MAP_AttributeCertificate_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t AttributeCertificate_desc = {
    "AttributeCertificate",
    "AttributeCertificate",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    AttributeCertificate_desc_tags_1,
    sizeof(AttributeCertificate_desc_tags_1)
    / sizeof(AttributeCertificate_desc_tags_1[0]), /* 1 */
    AttributeCertificate_desc_tags_1,    /* Same as above */
    sizeof(AttributeCertificate_desc_tags_1)
    / sizeof(AttributeCertificate_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_AttributeCertificate_1,
    3,    /* Elements count */
    &asn_SPC_AttributeCertificate_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_AttributeCertificate_desc(void)
{
    return &AttributeCertificate_desc;
}
