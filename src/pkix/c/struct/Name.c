/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "Name.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/Name.c"

static asn_TYPE_member_t asn_MBR_Name_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct Name, choice.rdnSequence),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &RDNSequence_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "rdnSequence"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_Name_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* rdnSequence */
};
static asn_CHOICE_specifics_t asn_SPC_Name_specs_1 = {
    sizeof(struct Name),
    offsetof(struct Name, _asn_ctx),
    offsetof(struct Name, present),
    sizeof(((struct Name *)0)->present),
    asn_MAP_Name_tag2el_1,
    1,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t Name_desc = {
    "Name",
    "Name",
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
    asn_MBR_Name_1,
    1,    /* Elements count */
    &asn_SPC_Name_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_Name_desc(void)
{
    return &Name_desc;
}
