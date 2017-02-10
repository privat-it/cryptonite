/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OtherName.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OtherName.c"

static asn_TYPE_member_t asn_MBR_OtherName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OtherName, type_id),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OBJECT_IDENTIFIER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "type-id"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct OtherName, value),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &ANY_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "value"
    },
};
static const ber_tlv_tag_t OtherName_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OtherName_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 }, /* type-id */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* value */
};
static asn_SEQUENCE_specifics_t asn_SPC_OtherName_specs_1 = {
    sizeof(struct OtherName),
    offsetof(struct OtherName, _asn_ctx),
    asn_MAP_OtherName_tag2el_1,
    2,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OtherName_desc = {
    "OtherName",
    "OtherName",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OtherName_desc_tags_1,
    sizeof(OtherName_desc_tags_1)
    / sizeof(OtherName_desc_tags_1[0]), /* 1 */
    OtherName_desc_tags_1,    /* Same as above */
    sizeof(OtherName_desc_tags_1)
    / sizeof(OtherName_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OtherName_1,
    2,    /* Elements count */
    &asn_SPC_OtherName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OtherName_desc(void)
{
    return &OtherName_desc;
}
