/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CrlIdentifier.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CrlIdentifier.c"

static asn_TYPE_member_t asn_MBR_CrlIdentifier_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CrlIdentifier, crlissuer),
        -1 /* Ambiguous tag (CHOICE?) */,
        0,
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlissuer"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CrlIdentifier, crlIssuedTime),
        (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),
        0,
        &UTCTime_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlIssuedTime"
    },
    {
        ATF_POINTER, 1, offsetof(struct CrlIdentifier, crlNumber),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &INTEGER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "crlNumber"
    },
};
static const ber_tlv_tag_t CrlIdentifier_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CrlIdentifier_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, 0, 0 }, /* crlNumber */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* rdnSequence */
    { (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)), 1, 0, 0 } /* crlIssuedTime */
};
static asn_SEQUENCE_specifics_t asn_SPC_CrlIdentifier_specs_1 = {
    sizeof(struct CrlIdentifier),
    offsetof(struct CrlIdentifier, _asn_ctx),
    asn_MAP_CrlIdentifier_tag2el_1,
    3,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t CrlIdentifier_desc = {
    "CrlIdentifier",
    "CrlIdentifier",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    CrlIdentifier_desc_tags_1,
    sizeof(CrlIdentifier_desc_tags_1)
    / sizeof(CrlIdentifier_desc_tags_1[0]), /* 1 */
    CrlIdentifier_desc_tags_1,    /* Same as above */
    sizeof(CrlIdentifier_desc_tags_1)
    / sizeof(CrlIdentifier_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CrlIdentifier_1,
    3,    /* Elements count */
    &asn_SPC_CrlIdentifier_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CrlIdentifier_desc(void)
{
    return &CrlIdentifier_desc;
}
