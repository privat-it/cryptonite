/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "DigestedData.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/DigestedData.c"

static asn_TYPE_member_t asn_MBR_DigestedData_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct DigestedData, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CMSVersion_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct DigestedData, digestAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &DigestAlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "digestAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct DigestedData, encapContentInfo),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &EncapsulatedContentInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "encapContentInfo"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct DigestedData, digest),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &Digest_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "digest"
    },
};
static const ber_tlv_tag_t DigestedData_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DigestedData_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 3, 0, 0 }, /* digest */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 1 }, /* digestAlgorithm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 0 } /* encapContentInfo */
};
static asn_SEQUENCE_specifics_t asn_SPC_DigestedData_specs_1 = {
    sizeof(struct DigestedData),
    offsetof(struct DigestedData, _asn_ctx),
    asn_MAP_DigestedData_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t DigestedData_desc = {
    "DigestedData",
    "DigestedData",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    DigestedData_desc_tags_1,
    sizeof(DigestedData_desc_tags_1)
    / sizeof(DigestedData_desc_tags_1[0]), /* 1 */
    DigestedData_desc_tags_1,    /* Same as above */
    sizeof(DigestedData_desc_tags_1)
    / sizeof(DigestedData_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_DigestedData_1,
    4,    /* Elements count */
    &asn_SPC_DigestedData_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_DigestedData_desc(void)
{
    return &DigestedData_desc;
}
