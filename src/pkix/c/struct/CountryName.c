/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "CountryName.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/CountryName.c"

static asn_TYPE_member_t asn_MBR_CountryName_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct CountryName, choice.x121_dcc_code),
        (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)),
        0,
        &NumericString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "x121-dcc-code"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct CountryName, choice.iso_3166_alpha2_code),
        (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)),
        0,
        &PrintableString_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "iso-3166-alpha2-code"
    },
};
static const ber_tlv_tag_t CountryName_desc_tags_1[] = {
    (ASN_TAG_CLASS_APPLICATION | (1 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CountryName_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (18 << 2)), 0, 0, 0 }, /* x121-dcc-code */
    { (ASN_TAG_CLASS_UNIVERSAL | (19 << 2)), 1, 0, 0 } /* iso-3166-alpha2-code */
};
static asn_CHOICE_specifics_t asn_SPC_CountryName_specs_1 = {
    sizeof(struct CountryName),
    offsetof(struct CountryName, _asn_ctx),
    offsetof(struct CountryName, present),
    sizeof(((struct CountryName *)0)->present),
    asn_MAP_CountryName_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t CountryName_desc = {
    "CountryName",
    "CountryName",
    CHOICE_free,
    CHOICE_print,
    CHOICE_constraint,
    CHOICE_decode_ber,
    CHOICE_encode_der,
    CHOICE_decode_xer,
    CHOICE_encode_xer,
    0, 0,    /* No PER support, use "-gen-PER" to enable */
    CHOICE_outmost_tag,
    CountryName_desc_tags_1,
    sizeof(CountryName_desc_tags_1)
    / sizeof(CountryName_desc_tags_1[0]), /* 1 */
    CountryName_desc_tags_1,    /* Same as above */
    sizeof(CountryName_desc_tags_1)
    / sizeof(CountryName_desc_tags_1[0]), /* 1 */
    0,    /* No PER visible constraints */
    asn_MBR_CountryName_1,
    2,    /* Elements count */
    &asn_SPC_CountryName_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_CountryName_desc(void)
{
    return &CountryName_desc;
}
