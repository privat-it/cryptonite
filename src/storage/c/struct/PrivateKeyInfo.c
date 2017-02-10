/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PrivateKeyInfo.h"

#include "asn_internal.h"

#include "Attributes.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PrivateKeyInfo.c"

static asn_TYPE_member_t asn_MBR_PrivateKeyInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateKeyInfo, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &Version_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateKeyInfo, privateKeyAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &AlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "privateKeyAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct PrivateKeyInfo, privateKey),
        (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
        0,
        &OCTET_STRING_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "privateKey"
    },
    {
        ATF_POINTER, 1, offsetof(struct PrivateKeyInfo, attributes),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &Attributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "attributes"
    },
};
static const ber_tlv_tag_t PrivateKeyInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PrivateKeyInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 2, 0, 0 }, /* privateKey */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 }, /* privateKeyAlgorithm */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 3, 0, 0 } /* attributes */
};
static asn_SEQUENCE_specifics_t asn_SPC_PrivateKeyInfo_specs_1 = {
    sizeof(struct PrivateKeyInfo),
    offsetof(struct PrivateKeyInfo, _asn_ctx),
    asn_MAP_PrivateKeyInfo_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t PrivateKeyInfo_desc = {
    "PrivateKeyInfo",
    "PrivateKeyInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    PrivateKeyInfo_desc_tags_1,
    sizeof(PrivateKeyInfo_desc_tags_1)
    / sizeof(PrivateKeyInfo_desc_tags_1[0]), /* 1 */
    PrivateKeyInfo_desc_tags_1,    /* Same as above */
    sizeof(PrivateKeyInfo_desc_tags_1)
    / sizeof(PrivateKeyInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_PrivateKeyInfo_1,
    4,    /* Elements count */
    &asn_SPC_PrivateKeyInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PrivateKeyInfo_desc(void)
{
    return &PrivateKeyInfo_desc;
}
