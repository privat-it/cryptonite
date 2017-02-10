/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CrlID.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CrlID.c"

static asn_TYPE_member_t asn_MBR_CrlID_1[] = {
    {
        ATF_POINTER, 3, offsetof(struct CrlID, crlUrl),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &IA5String_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlUrl"
    },
    {
        ATF_POINTER, 2, offsetof(struct CrlID, crlNum),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlNum"
    },
    {
        ATF_POINTER, 1, offsetof(struct CrlID, crlTime),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &GeneralizedTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlTime"
    },
};
static const ber_tlv_tag_t CrlID_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CrlID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* crlUrl */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* crlNum */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* crlTime */
};
static asn_SEQUENCE_specifics_t asn_SPC_CrlID_specs_1 = {
    sizeof(struct CrlID),
    offsetof(struct CrlID, _asn_ctx),
    asn_MAP_CrlID_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CrlID_desc = {
    "CrlID",
    "CrlID",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CrlID_desc_tags_1,
    sizeof(CrlID_desc_tags_1)
    / sizeof(CrlID_desc_tags_1[0]), /* 1 */
    CrlID_desc_tags_1,    /* Same as above */
    sizeof(CrlID_desc_tags_1)
    / sizeof(CrlID_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CrlID_1,
    3,    /* Elements count */
    &asn_SPC_CrlID_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CrlID_desc(void)
{
    return &CrlID_desc;
}
