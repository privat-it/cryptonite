/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "SafeBag.h"

#include "asn_internal.h"

#include "Attributes.h"
#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/SafeBag.c"

static asn_TYPE_member_t asn_MBR_SafeBag_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct SafeBag, bagId),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OBJECT_IDENTIFIER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "bagId"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct SafeBag, bagValue),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &ANY_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "bagValue"
    },
    {
        ATF_POINTER, 1, offsetof(struct SafeBag, bagAttributes),
        (ASN_TAG_CLASS_UNIVERSAL | (17 << 2)),
        0,
        &Attributes_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "bagAttributes"
    },
};
static const ber_tlv_tag_t SafeBag_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_SafeBag_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 }, /* bagId */
    { (ASN_TAG_CLASS_UNIVERSAL | (17 << 2)), 2, 0, 0 }, /* bagAttributes */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* bagValue */
};
static asn_SEQUENCE_specifics_t asn_SPC_SafeBag_specs_1 = {
    sizeof(struct SafeBag),
    offsetof(struct SafeBag, _asn_ctx),
    asn_MAP_SafeBag_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t SafeBag_desc = {
    "SafeBag",
    "SafeBag",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    SafeBag_desc_tags_1,
    sizeof(SafeBag_desc_tags_1)
    / sizeof(SafeBag_desc_tags_1[0]), /* 1 */
    SafeBag_desc_tags_1,    /* Same as above */
    sizeof(SafeBag_desc_tags_1)
    / sizeof(SafeBag_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_SafeBag_1,
    3,    /* Elements count */
    &asn_SPC_SafeBag_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_SafeBag_desc(void)
{
    return &SafeBag_desc;
}
