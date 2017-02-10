/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "KeyAgreeRecipientInfo.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/KeyAgreeRecipientInfo.c"

static asn_TYPE_member_t asn_MBR_KeyAgreeRecipientInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientInfo, version),
        (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
        0,
        &CMSVersion_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "version"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientInfo, originator),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &OriginatorIdentifierOrKey_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "originator"
    },
    {
        ATF_POINTER, 1, offsetof(struct KeyAgreeRecipientInfo, ukm),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &UserKeyingMaterial_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ukm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientInfo, keyEncryptionAlgorithm),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &KeyEncryptionAlgorithmIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "keyEncryptionAlgorithm"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientInfo, recipientEncryptedKeys),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &RecipientEncryptedKeys_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "recipientEncryptedKeys"
    },
};
static const ber_tlv_tag_t KeyAgreeRecipientInfo_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_KeyAgreeRecipientInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, 0, 1 }, /* keyEncryptionAlgorithm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -1, 0 }, /* recipientEncryptedKeys */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 }, /* originator */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 2, 0, 0 } /* ukm */
};
static asn_SEQUENCE_specifics_t asn_SPC_KeyAgreeRecipientInfo_specs_1 = {
    sizeof(struct KeyAgreeRecipientInfo),
    offsetof(struct KeyAgreeRecipientInfo, _asn_ctx),
    asn_MAP_KeyAgreeRecipientInfo_tag2el_1,
    5,    /* Count of tags in the map */
    0, 0, 0,    /* Optional elements (not needed) */
    -1,    /* Start extensions */
    -1    /* Stop extensions */
};
asn_TYPE_descriptor_t KeyAgreeRecipientInfo_desc = {
    "KeyAgreeRecipientInfo",
    "KeyAgreeRecipientInfo",
    SEQUENCE_free,
    SEQUENCE_print,
    SEQUENCE_constraint,
    SEQUENCE_decode_ber,
    SEQUENCE_encode_der,
    SEQUENCE_decode_xer,
    SEQUENCE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    KeyAgreeRecipientInfo_desc_tags_1,
    sizeof(KeyAgreeRecipientInfo_desc_tags_1)
    / sizeof(KeyAgreeRecipientInfo_desc_tags_1[0]), /* 1 */
    KeyAgreeRecipientInfo_desc_tags_1,    /* Same as above */
    sizeof(KeyAgreeRecipientInfo_desc_tags_1)
    / sizeof(KeyAgreeRecipientInfo_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_KeyAgreeRecipientInfo_1,
    5,    /* Elements count */
    &asn_SPC_KeyAgreeRecipientInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_KeyAgreeRecipientInfo_desc(void)
{
    return &KeyAgreeRecipientInfo_desc;
}
