/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "DSTUEllipticCurve.h"

#include "asn_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "pkix/struct/DSTUEllipticCurve.c"

static asn_TYPE_member_t asn_MBR_DSTUEllipticCurve_1[] = {
    {
        ATF_NOFLAGS, 0, offsetof(struct DSTUEllipticCurve, choice.ecbinary),
        (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
        0,
        &ECBinary_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "ecbinary"
    },
    {
        ATF_NOFLAGS, 0, offsetof(struct DSTUEllipticCurve, choice.namedCurve),
        (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
        0,
        &OBJECT_IDENTIFIER_desc,
        0,    /* Defer constraints checking to the member type */
        0,    /* PER is not compiled, use -gen-PER */
        0,
        "namedCurve"
    },
};
static const asn_TYPE_tag2member_t asn_MAP_DSTUEllipticCurve_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 1, 0, 0 }, /* namedCurve */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 0 } /* ecbinary */
};
static asn_CHOICE_specifics_t asn_SPC_DSTUEllipticCurve_specs_1 = {
    sizeof(struct DSTUEllipticCurve),
    offsetof(struct DSTUEllipticCurve, _asn_ctx),
    offsetof(struct DSTUEllipticCurve, present),
    sizeof(((struct DSTUEllipticCurve *)0)->present),
    asn_MAP_DSTUEllipticCurve_tag2el_1,
    2,    /* Count of tags in the map */
    0,
    -1    /* Extensions start */
};
asn_TYPE_descriptor_t DSTUEllipticCurve_desc = {
    "DSTUEllipticCurve",
    "DSTUEllipticCurve",
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
    asn_MBR_DSTUEllipticCurve_1,
    2,    /* Elements count */
    &asn_SPC_DSTUEllipticCurve_specs_1    /* Additional specs */
};

asn_TYPE_descriptor_t *get_DSTUEllipticCurve_desc(void)
{
    return &DSTUEllipticCurve_desc;
}
