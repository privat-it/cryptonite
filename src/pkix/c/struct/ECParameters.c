/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "ECParameters.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/ECParameters.c"

static asn_TYPE_member_t asn_MBR_ECParameters_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct ECParameters, choice.namedCurve),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OBJECT_IDENTIFIER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "namedCurve"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_ECParameters_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 } /* namedCurve */
};
static asn_CHOICE_specifics_t asn_SPC_ECParameters_specs_1 = {
    sizeof(struct ECParameters),
    offsetof(struct ECParameters, _asn_ctx),
    offsetof(struct ECParameters, present),
    sizeof(((struct ECParameters *)0)->present),
    asn_MAP_ECParameters_tag2el_1,
    1,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t ECParameters_desc = {
    "ECParameters",
    "ECParameters",
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
    asn_MBR_ECParameters_1,
    1,    /* Elements count */
    &asn_SPC_ECParameters_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_ECParameters_desc(void)
{
    return &ECParameters_desc;
}
