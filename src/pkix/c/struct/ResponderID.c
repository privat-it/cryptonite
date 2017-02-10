/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ResponderID.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/ResponderID.c"

static asn_TYPE_member_t asn_MBR_ResponderID_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct ResponderID, choice.byName),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &Name_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "byName"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct ResponderID, choice.byKey),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        +1,    /* EXPLICIT tag at current level */
        &KeyHash_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "byKey"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_ResponderID_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 0, 0, 0 }, /* byName */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 1, 0, 0 } /* byKey */
};
static asn_CHOICE_specifics_t asn_SPC_ResponderID_specs_1 = {
    sizeof(struct ResponderID),
    offsetof(struct ResponderID, _asn_ctx),
    offsetof(struct ResponderID, present),
    sizeof(((struct ResponderID *)0)->present),
    asn_MAP_ResponderID_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t ResponderID_desc = {
    "ResponderID",
    "ResponderID",
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
    asn_MBR_ResponderID_1,
    2,    /* Elements count */
    &asn_SPC_ResponderID_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_ResponderID_desc(void)
{
    return &ResponderID_desc;
}
