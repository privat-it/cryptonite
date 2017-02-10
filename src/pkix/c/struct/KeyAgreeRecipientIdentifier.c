/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "KeyAgreeRecipientIdentifier.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/KeyAgreeRecipientIdentifier.c"

static asn_TYPE_member_t asn_MBR_KeyAgreeRecipientIdentifier_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientIdentifier, choice.issuerAndSerialNumber),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &IssuerAndSerialNumber_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "issuerAndSerialNumber"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct KeyAgreeRecipientIdentifier, choice.rKeyId),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &RecipientKeyIdentifier_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "rKeyId"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_KeyAgreeRecipientIdentifier_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 }, /* issuerAndSerialNumber */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* rKeyId */
};
static asn_CHOICE_specifics_t asn_SPC_KeyAgreeRecipientIdentifier_specs_1 = {
    sizeof(struct KeyAgreeRecipientIdentifier),
    offsetof(struct KeyAgreeRecipientIdentifier, _asn_ctx),
    offsetof(struct KeyAgreeRecipientIdentifier, present),
    sizeof(((struct KeyAgreeRecipientIdentifier *)0)->present),
    asn_MAP_KeyAgreeRecipientIdentifier_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t KeyAgreeRecipientIdentifier_desc = {
    "KeyAgreeRecipientIdentifier",
    "KeyAgreeRecipientIdentifier",
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
    asn_MBR_KeyAgreeRecipientIdentifier_1,
    2,    /* Elements count */
    &asn_SPC_KeyAgreeRecipientIdentifier_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_KeyAgreeRecipientIdentifier_desc(void)
{
    return &KeyAgreeRecipientIdentifier_desc;
}
