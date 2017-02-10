/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "RecipientInfo.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/RecipientInfo.c"

static asn_TYPE_member_t asn_MBR_RecipientInfo_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientInfo, choice.ktri),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &KeyTransRecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ktri"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientInfo, choice.kari),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &KeyAgreeRecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "kari"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientInfo, choice.kekri),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &KEKRecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "kekri"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientInfo, choice.pwri),
        (ASN_TAG_CLASS_CONTEXT | (3 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &PasswordRecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "pwri"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct RecipientInfo, choice.ori),
        (ASN_TAG_CLASS_CONTEXT | (4 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &OtherRecipientInfo_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ori"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_RecipientInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* ktri */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* kari */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* kekri */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* pwri */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 } /* ori */
};
static asn_CHOICE_specifics_t asn_SPC_RecipientInfo_specs_1 = {
    sizeof(struct RecipientInfo),
    offsetof(struct RecipientInfo, _asn_ctx),
    offsetof(struct RecipientInfo, present),
    sizeof(((struct RecipientInfo *)0)->present),
    asn_MAP_RecipientInfo_tag2el_1,
    5,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t RecipientInfo_desc = {
    "RecipientInfo",
    "RecipientInfo",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    0,    /* No effective tags (pointer) */
    0,    /* No effective tags (count) */
    0,    /* No tags (pointer) */
    0,    /* No tags (count) */
    0,    /* No PER visible constraints */
    asn_MBR_RecipientInfo_1,
    5,    /* Elements count */
    &asn_SPC_RecipientInfo_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_RecipientInfo_desc(void)
{
    return &RecipientInfo_desc;
}
