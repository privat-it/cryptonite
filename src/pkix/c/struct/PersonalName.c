/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "PersonalName.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/PersonalName.c"

static asn_TYPE_member_t asn_MBR_PersonalName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct PersonalName, surname),
        (ASN_TAG_CLASS_CONTEXT | (0 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "surname"
    },
    {
        ATF_POINTER, 3, offsetof(struct PersonalName, given_name),
        (ASN_TAG_CLASS_CONTEXT | (1 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "given-name"
    },
    {
        ATF_POINTER, 2, offsetof(struct PersonalName, initials),
        (ASN_TAG_CLASS_CONTEXT | (2 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "initials"
    },
    {
        ATF_POINTER, 1, offsetof(struct PersonalName, generation_qualifier),
        (ASN_TAG_CLASS_CONTEXT | (3 << 2)),
        -1,    /* IMPLICIT tag at current level */
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "generation-qualifier"
    },
};
static const ber_tlv_tag_t PersonalName_desc_tags_1[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PersonalName_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* surname */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* given-name */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* initials */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* generation-qualifier */
};
static const uint8_t asn_MAP_PersonalName_mmap_1[(4 + (8 * sizeof(unsigned int)) - 1) / 8] = {
    (1 << 7) | (0 << 6) | (0 << 5) | (0 << 4)
};
static asn_SET_specifics_t asn_SPC_PersonalName_specs_1 = {
    sizeof(struct PersonalName),
    offsetof(struct PersonalName, _asn_ctx),
    offsetof(struct PersonalName, _presence_map),
    asn_MAP_PersonalName_tag2el_1,
    4,    /* Count of tags in the map */
    asn_MAP_PersonalName_tag2el_1,    /* Same as above */
    4,    /* Count of tags in the CXER map */
    0,    /* Whether extensible */
    (unsigned int *)asn_MAP_PersonalName_mmap_1    /* Mandatory elements map */
};
asn_TYPE_descriptor_t PersonalName_desc = {
    "PersonalName",
    "PersonalName",
    SET_free,
    SET_print,
    SET_constraint,
    SET_decode_ber,
    SET_encode_der,
    SET_decode_xer,
    SET_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    0,    /* Use generic outmost tag fetcher */
    PersonalName_desc_tags_1,
    sizeof(PersonalName_desc_tags_1)
    / sizeof(PersonalName_desc_tags_1[0]), /* 1 */
    PersonalName_desc_tags_1,    /* Same as above */
    sizeof(PersonalName_desc_tags_1)
    / sizeof(PersonalName_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_PersonalName_1,
    4,    /* Elements count */
    &asn_SPC_PersonalName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_PersonalName_desc(void)
{
    return &PersonalName_desc;
}
