/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "OtherHash.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/OtherHash.c"

static asn_TYPE_member_t asn_MBR_OtherHash_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct OtherHash, choice.otherHash),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &OtherHashAlgAndValue_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "otherHash"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_OtherHash_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* otherHash */
};
static asn_CHOICE_specifics_t asn_SPC_OtherHash_specs_1 = {
    sizeof(struct OtherHash),
    offsetof(struct OtherHash, _asn_ctx),
    offsetof(struct OtherHash, present),
    sizeof(((struct OtherHash *)0)->present),
    asn_MAP_OtherHash_tag2el_1,
    1,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t OtherHash_desc = {
    "OtherHash",
    "OtherHash",
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
    asn_MBR_OtherHash_1,
    1,    /* Elements count */
    &asn_SPC_OtherHash_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_OtherHash_desc(void)
{
    return &OtherHash_desc;
}
