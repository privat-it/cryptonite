/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OtherRevVals.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OtherRevVals.c"

static asn_TYPE_member_t asn_MBR_OtherRevVals_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OtherRevVals, otherRevValType),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OtherRevValType_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "otherRevValType"
    },
    {
        ATF_OPEN_TYPE | ATF_NOFLAGS, 0, offsetof(struct OtherRevVals, otherRevVals),
        -1 /* Ambiguous tag (ANY?) */,
        0,
        &ANY_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "otherRevVals"
    },
};
static const ber_tlv_tag_t OtherRevVals_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_OtherRevVals_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 } /* otherRevValType */
};
static asn_SEQUENCE_specifics_t asn_SPC_OtherRevVals_specs_1 = {
    sizeof(struct OtherRevVals),
    offsetof(struct OtherRevVals, _asn_ctx),
    asn_MAP_OtherRevVals_tag2el_1,
    1,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t OtherRevVals_desc = {
    "OtherRevVals",
    "OtherRevVals",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    OtherRevVals_desc_tags_1,
    sizeof(OtherRevVals_desc_tags_1)
    / sizeof(OtherRevVals_desc_tags_1[0]), /* 1 */
    OtherRevVals_desc_tags_1,    /* Same as above */
    sizeof(OtherRevVals_desc_tags_1)
    / sizeof(OtherRevVals_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_OtherRevVals_1,
    2,    /* Elements count */
    &asn_SPC_OtherRevVals_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OtherRevVals_desc(void)
{
    return &OtherRevVals_desc;
}
