/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "SPUserNotice.h"

#include "asn_internal.h"

#include "NoticeReference.h"
#include "DisplayText.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/SPUserNotice.c"

static asn_TYPE_member_t asn_MBR_SPUserNotice_1[] = {
    {
        ATF_POINTER, 2, offsetof(struct SPUserNotice, noticeRef),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &NoticeReference_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "noticeRef"
    },
    {
        ATF_POINTER, 1, offsetof(struct SPUserNotice, explicitText),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &DisplayText_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "explicitText"
    },
};
static const ber_tlv_tag_t SPUserNotice_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SPUserNotice_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (12 << 2)), 1, 0, 0 }, /* utf8String */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* noticeRef */
    { (ASN_TAG_CLASS_UNIVERSAL | (26 << 2)), 1, 0, 0 }, /* visibleString */
    { (ASN_TAG_CLASS_UNIVERSAL | (30 << 2)), 1, 0, 0 } /* bmpString */
};
static asn_SEQUENCE_specifics_t asn_SPC_SPUserNotice_specs_1 = {
    sizeof(struct SPUserNotice),
    offsetof(struct SPUserNotice, _asn_ctx),
    asn_MAP_SPUserNotice_tag2el_1,
    4,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t SPUserNotice_desc = {
    "SPUserNotice",
    "SPUserNotice",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    SPUserNotice_desc_tags_1,
    sizeof(SPUserNotice_desc_tags_1)
    / sizeof(SPUserNotice_desc_tags_1[0]), /* 1 */
    SPUserNotice_desc_tags_1,    /* Same as above */
    sizeof(SPUserNotice_desc_tags_1)
    / sizeof(SPUserNotice_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_SPUserNotice_1,
    2,    /* Elements count */
    &asn_SPC_SPUserNotice_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_SPUserNotice_desc(void)
{
    return &SPUserNotice_desc;
}
