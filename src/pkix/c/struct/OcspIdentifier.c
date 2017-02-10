/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OcspIdentifier.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OcspIdentifier.c"

static asn_TYPE_member_t asn_MBR_OcspIdentifier_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OcspIdentifier, ocspResponderID),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &ResponderID_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ocspResponderID"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct OcspIdentifier, producedAt),
        (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)),
        0,
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "producedAt"
    },
};
static const ber_tlv_tag_t OcspIdentifier_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OcspIdentifier_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (24 << 2)), 1, 0, 0 }, /* producedAt */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 0, 0, 0 }, /* byName */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 0, 0, 0 } /* byKey */
};
static asn_SEQUENCE_specifics_t asn_SPC_OcspIdentifier_specs_1 = {
    sizeof(struct OcspIdentifier),
    offsetof(struct OcspIdentifier, _asn_ctx),
    asn_MAP_OcspIdentifier_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OcspIdentifier_desc = {
    "OcspIdentifier",
    "OcspIdentifier",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OcspIdentifier_desc_tags_1,
    sizeof(OcspIdentifier_desc_tags_1)
    / sizeof(OcspIdentifier_desc_tags_1[0]), /* 1 */
    OcspIdentifier_desc_tags_1,    /* Same as above */
    sizeof(OcspIdentifier_desc_tags_1)
    / sizeof(OcspIdentifier_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OcspIdentifier_1,
    2,    /* Elements count */
    &asn_SPC_OcspIdentifier_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OcspIdentifier_desc(void)
{
    return &OcspIdentifier_desc;
}
